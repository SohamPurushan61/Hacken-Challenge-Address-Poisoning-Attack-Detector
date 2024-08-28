import requests
from web3 import Web3

web3 = Web3(Web3.HTTPProvider("your_node_url"))

# placeholder for fetching top 100 tokens need to be fleshed out
def fetch_top_tokens():
    response = requests.get('https://api.coingecko.com/api/v3/coins/markets', params={'vs_currency': 'usd', 'order': 'market_cap_desc', 'per_page': 100, 'page': 1})
    return response.json()

# Function to update whale addresses
def update_whale_addresses(tokens):
    whale_addresses = []
    for token in tokens:
        token_contract = web3.eth.contract(address=Web3.toChecksumAddress(token['contract_address']), abi=fetch.get_abi(token['id']))
        total_supply = token_contract.functions.totalSupply().call()
        for i in range(0, 100):  #
            holder = token_contract.functions.holderByIndex(i).call()  # Example function; adjust based on actual ABI
            balance = token_contract.functions.balanceOf(holder).call()
            if balance >= 100_000:
                whale_addresses.append(holder)
    return whale_addresses

# Store whale addresses db
def store_whale_addresses(whale_addresses):
    common.store_in_db('whale_addresses', whale_addresses)  # Assuming common.py has a DB interaction function

if __name__ == "__main__":
    tokens = fetch_top_tokens()
    whale_addresses = update_whale_addresses(tokens)
    store_whale_addresses(whale_addresses)
