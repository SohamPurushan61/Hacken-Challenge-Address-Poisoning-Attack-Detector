import pathlib
import requests
import time
import uuid
from typing import List
from sentinel.definitions import BLOCKCHAIN
from sentinel.sentry.v2.block_tx import BlockTxDetector
from sentinel.models.database import Database
from sentinel.models.event import Event, Blockchain
from sentinel.models.transaction import Transaction
from sentinel.db.contract.abi.erc20 import ERC20 as ERC20_ABI
from sentinel.utils.web3 import get_async_web3
from sentinel.utils.transaction import filter_events
from sentinel.db.contract.abi.static import ABI_EVENT_TRANSFER
from sentinel.db.label_db.local import LabelDB


class V2LabelDB(LabelDB):
    
    def __init__(self, path: pathlib.Path, update_tags: List[str] = [], update_interval: int = 120, **kwargs) -> None:
        super().__init__(path, update_tags, update_interval, **kwargs)
    
    @classmethod
    def from_settings(cls, settings: Database, **kwargs):
        path = settings.parameters.pop("path")
        kwargs.update(settings.parameters)
        return cls(path=path, **kwargs)
    

class AddressPoisoningDetector(BlockTxDetector):
    name = "BalanceMonitor"
    description = "Monitors Account/Contract balance (native token)"

    async def on_init(self):
        self.logger.info("Initialization started")
        self.w3 = get_async_web3(self.parameters.get("rpc"))
        self.native = self.parameters.get("native", "ETH")
        self.decimals = 10 ** self.parameters.get("decimals", 18)
        self.severity = self.parameters.get("severity", 0.15)
        
        self._whale_wallet_map = await self.initialize_whale_wallets()
        self.erc20_token_address_map = self.retrieve_tokens()

    async def initialize_whale_wallets(self):
        whale_wallets = await self.databases.label.search_by_tag(["whale"])
        whale_wallet_map = {}
        for whale in whale_wallets:
            whale_wallet_map[whale.address] = {
                "balance": 0,
                "to": set(),
                "poisoned_address": set()
            }
        return whale_wallet_map

    def retrieve_tokens(self):
        url = 'https://api.coingecko.com/api/v3/coins/markets'
        params = {  
            'order': 'market_cap_desc',
            'vs_currency': 'usd',
            'category': 'ethereum-ecosystem',
            'per_page': '10'
        }
        headers = { 
            'x-cg-demo-api-key': 'CG-KMa6FtrxFXynowqRYUzWyK2T',
            'accept': 'application/json' 
        }

        response = self.safe_request(url, params=params, headers=headers)
        if not response:
            return {}

        token_address_map = {}
        for token in response:
            token_address_map.update(self.process_token(token))
        
        return token_address_map

    def safe_request(self, url, params=None, headers=None):
        try:
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {e}")
            return None

    def process_token(self, token):
        token_data = {}
        coin_details = self.safe_request(
            f"https://api.coingecko.com/api/v3/coins/{token['id']}",
            params={
                'localization': 'false',
                'tickers': 'false',
                'market_data': 'true',
                'community_data': 'false',
                'developer_data': 'false',
                'sparkline': 'false'
            },
            headers={
                'x-cg-demo-api-key': 'CG-KMa6FtrxFXynowqRYUzWyK2T',
                'accept': 'application/json'
            }
        )
        
        if not coin_details or "ethereum" not in coin_details["detail_platforms"]:
            return {}

        contract_address = coin_details["detail_platforms"]["ethereum"]["contract_address"]
        token_data[contract_address] = {
            "id": token["id"],
            "price": token["current_price"],
            "symbol": token["symbol"],
            "name": token["name"],
            "contract": self.w3.eth.contract(
                address=self.w3.to_checksum_address(contract_address), 
                abi=ERC20_ABI
            )
        }
        return token_data

    async def calculate_address_balance(self, addr: str) -> int:
        total_usd = 0
        total_usd += await self.calculate_native_balance(addr)
        total_usd += await self.calculate_erc20_balances(addr)
        self.logger.info(f"Total balance USD: {total_usd}")
        return total_usd
    
    async def calculate_native_balance(self, addr: str) -> int:
        balance = await self.ask_balance(addr)
        return (balance * self.eth_price) / self.decimals

    async def calculate_erc20_balances(self, addr: str) -> int:
        total_usd = 0
        for erc20 in self.erc20_token_address_map.values():
            balance = await self.ask_erc20_balance(addr, erc20["contract"], erc20["symbol"])
            total_usd += (balance * erc20["price"]) / (10 ** erc20["decimal_place"])
        return total_usd

    async def calculate_transaction_value(self, balance) -> int:
        return (balance * self.eth_price) / self.decimals
    
    async def calculate_erc20_value(self, contract_address, value) -> int:
        if contract_address in self.erc20_token_address_map:
            return (value * self.erc20_token_address_map[contract_address]["price"]) / (10 ** self.erc20_token_address_map[contract_address]["decimal_place"])
        return 0

    async def ask_balance(self, addr: str) -> int:
        balance = await self.w3.eth.get_balance(self.w3.to_checksum_address(addr))
        self.logger.debug(f"Balance: {addr}: {balance}")
        return balance

    async def ask_erc20_balance(self, addr: str, erc20_contract: any, erc20_symbol: str) -> int:
        balance = await erc20_contract.functions.balanceOf(self.w3.to_checksum_address(addr)).call()
        self.logger.debug(f"ERC20 Balance: {addr}: {erc20_symbol}={balance}")
        return balance
    
    def check_if_address_mime(self, addrA: str, addrB: str):
        return (
            addrA != addrB and 
            any(addrA.startswith(addrB[:i]) for i in range(4, 7)) and
            any(addrA.endswith(addrB[-i:]) for i in range(3, 6))
        )

    async def on_block(self, transactions: List[Transaction]) -> None:
        if not transactions:
            return

        self.logger.info(f"Block: {transactions[0].block.number}")
        for tx in transactions:
            await self.process_transaction(tx)

    async def process_transaction(self, tx: Transaction) -> None:
        if tx.input == '0x' and await self.calculate_transaction_value(tx.value) > 100000:
            await self.label_whale(tx.from_address)
            await self.label_whale(tx.to_address)

        for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
            if await self.calculate_erc20_value(tx_event.address, tx_event.fields["value"]) > 100000:
                await self.label_whale(tx_event.fields["from"])
                await self.label_whale(tx_event.fields["to"])

        if tx.from_address in self._whale_wallet_map and tx.input == "0x":
            self._whale_wallet_map[tx.from_address]["to"].add(tx.to_address)

        for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
            if tx_event.fields.get("from", "0x") in self._whale_wallet_map:
                self._whale_wallet_map[tx_event.fields["from"]]["to"].add(tx_event.fields["to"])

        await self.detect_poisoning(tx)

    async def label_whale(self, address: str) -> None:
        if address not in self._whale_wallet_map:
            await self.databases.label.add(address, ["whale"], "native")
            self._whale_wallet_map[address] = {
                "balance": 0,
                "to": set(),
                "poisoned_address": set()
            }

    async def detect_poisoning(self, tx: Transaction) -> None:
        if tx.input == "0x" and tx.to_address in self._whale_wallet_map:
            await self.check_for_poisoning_attack(tx)

        for tx_event in filter_events(tx.logs, [ABI_EVENT_TRANSFER]):
            if tx_event.fields.get("from", "0x") in self._whale_wallet_map:
                await self.check_for_event_poisoning(tx, tx_event)

    async def check_for_poisoning_attack(self, tx: Transaction) -> None:
        for _to_addr in self._whale_wallet_map[tx.to_address]["to"]:
            if self.check_if_address_mime(_to_addr, tx.from_address):
                self.logger.info(f"Possible Address Poisoning Attack\n Transaction Hash: [{tx.hash}]\n Detail: {tx.from_address} mimes {_to_addr} targeting {tx.to_address}\n")
                self._whale_wallet_map[tx.to_address]["poisoned_address"].add(tx.from_address)

    async def check_for_event_poisoning(self, tx: Transaction, tx_event) -> None:
        for _to_addr in self._whale_wallet_map[tx_event.fields["from"]]["to"]:
            if self.check_if_address_mime(_to_addr, tx_event.fields["to"]) and await self.calculate_erc20_value(tx_event.address, tx_event.fields["value"]) < 10:
                self.logger.info(f"Possible Address Poisoning Attack Event\n Transaction Hash: [{tx.hash}]\n Detail: {tx_event.fields['to']} mimes {_to_addr} targeting {tx_event.fields['from']}\n")
                self._whale_wallet_map[tx_event.fields["from"]]["poisoned_address"].add(tx_event.fields['to'])

    async def send_notification(self, addr: str, token: str, balance: int, tx: Transaction = None) -> None:
        tx_details = {
            "ts": tx.block.timestamp if tx else int(time.time() * 1000),
            "hash": tx.hash if tx else "",
            "from": tx.from_address if tx else "",
            "to": tx.to_address if tx else "",
            "value": tx.value if tx else balance
        }

        self.logger.info(f"--> Event: {tx_details['ts']}: {addr}, {balance}, {tx}")

        await self.outputs.outbound_file_channel.send(
            Event(
                did=f"{self.name}-{token}",
                eid=uuid.uuid4().hex,
                type="balance_threshold",
                severity=self.severity,
                sid="ext:sentinel",
                ts=tx_details["ts"],
                blockchain=Blockchain(
                    network=self.parameters["network"],
                    chain_id=str(BLOCKCHAIN.get(self.parameters["network"]).chain_id),
                ),
                metadata={
                    "tx_hash": tx_details["hash"],
                    "tx_from": tx_details["from"],
                    "tx_to": tx_details["to"],
                    "token": token,
                    "value": tx_details["value"],
                    "monitored_contract": addr,
                    "balance": balance,
                    "desc": f"Address poisoning attack has been detected.",
                },
            )
        )
