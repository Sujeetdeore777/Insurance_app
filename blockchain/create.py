from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import os
import json
from dotenv import load_dotenv

# Load ENV file
load_dotenv()

CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
ADMIN_PRIVATE_KEY = os.getenv('ADMIN_PRIVATE_KEY')
RPC_URL = os.getenv('RPC_URL')
ADMIN_ACCOUNT_ADDRESS = os.getenv('ADMIN_ACCOUNT_ADDRESS')


contract_address = Web3.to_checksum_address(CONTRACT_ADDRESS)
# if os.path.exists('abi.json') == False:
#     raise Exception("Contract ABI not found !")


# with open('./abi.json') as json_file:
#     contract_abi = json.load(json_file)

contract_abi = """
[{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"id","type":"string"},{"indexed":false,"internalType":"string","name":"record_id","type":"string"},{"indexed":false,"internalType":"uint256","name":"recordIndex","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"string","name":"gender","type":"string"},{"indexed":false,"internalType":"uint16","name":"currentWeight","type":"uint16"},{"indexed":false,"internalType":"string","name":"currentHeight","type":"string"},{"indexed":false,"internalType":"string","name":"analysis","type":"string"},{"indexed":false,"internalType":"string","name":"bloodDetails","type":"string"},{"indexed":false,"internalType":"string","name":"bp","type":"string"},{"indexed":false,"internalType":"string","name":"bmi","type":"string"},{"indexed":false,"internalType":"uint8","name":"age","type":"uint8"},{"indexed":false,"internalType":"bool","name":"isDiabetic","type":"bool"},{"indexed":false,"internalType":"bool","name":"isAllergic","type":"bool"}],"name":"RecordCreated","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"id","type":"string"},{"indexed":false,"internalType":"uint256","name":"recordIndex","type":"uint256"}],"name":"RecordDeleted","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"id","type":"string"},{"indexed":false,"internalType":"string","name":"record_id","type":"string"},{"indexed":false,"internalType":"uint256","name":"recordIndex","type":"uint256"},{"indexed":false,"internalType":"string","name":"gender","type":"string"},{"indexed":false,"internalType":"uint16","name":"currentWeight","type":"uint16"},{"indexed":false,"internalType":"string","name":"currentHeight","type":"string"},{"indexed":false,"internalType":"string","name":"analysis","type":"string"},{"indexed":false,"internalType":"string","name":"bloodDetails","type":"string"},{"indexed":false,"internalType":"string","name":"bp","type":"string"},{"indexed":false,"internalType":"string","name":"bmi","type":"string"},{"indexed":false,"internalType":"uint8","name":"age","type":"uint8"},{"indexed":false,"internalType":"bool","name":"isDiabetic","type":"bool"},{"indexed":false,"internalType":"bool","name":"isAllergic","type":"bool"}],"name":"RecordUpdated","type":"event"},{"inputs":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"record_id","type":"string"},{"internalType":"string","name":"gender","type":"string"},{"internalType":"uint16","name":"currentWeight","type":"uint16"},{"internalType":"string","name":"currentHeight","type":"string"},{"internalType":"string","name":"analysis","type":"string"},{"internalType":"string","name":"bloodDetails","type":"string"},{"internalType":"string","name":"bp","type":"string"},{"internalType":"string","name":"bmi","type":"string"},{"internalType":"uint8","name":"age","type":"uint8"},{"internalType":"bool","name":"isDiabetic","type":"bool"},{"internalType":"bool","name":"isAllergic","type":"bool"}],"name":"createGeneralMedicineRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"record_id","type":"string"}],"name":"deleteGeneralMedicineRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"getGeneralMedicineRecords","outputs":[{"components":[{"internalType":"string","name":"record_id","type":"string"},{"internalType":"uint256","name":"timestamp","type":"uint256"},{"internalType":"string","name":"gender","type":"string"},{"internalType":"uint16","name":"currentWeight","type":"uint16"},{"internalType":"string","name":"currentHeight","type":"string"},{"internalType":"string","name":"analysis","type":"string"},{"internalType":"string","name":"bloodDetails","type":"string"},{"internalType":"string","name":"bp","type":"string"},{"internalType":"string","name":"bmi","type":"string"},{"internalType":"uint8","name":"age","type":"uint8"},{"internalType":"bool","name":"isDiabetic","type":"bool"},{"internalType":"bool","name":"isAllergic","type":"bool"}],"internalType":"struct HealthManagement.GeneralMedicine[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"record_id","type":"string"}],"name":"getRecordByRecordId","outputs":[{"components":[{"internalType":"string","name":"record_id","type":"string"},{"internalType":"uint256","name":"timestamp","type":"uint256"},{"internalType":"string","name":"gender","type":"string"},{"internalType":"uint16","name":"currentWeight","type":"uint16"},{"internalType":"string","name":"currentHeight","type":"string"},{"internalType":"string","name":"analysis","type":"string"},{"internalType":"string","name":"bloodDetails","type":"string"},{"internalType":"string","name":"bp","type":"string"},{"internalType":"string","name":"bmi","type":"string"},{"internalType":"uint8","name":"age","type":"uint8"},{"internalType":"bool","name":"isDiabetic","type":"bool"},{"internalType":"bool","name":"isAllergic","type":"bool"}],"internalType":"struct HealthManagement.GeneralMedicine","name":"","type":"tuple"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"record_id","type":"string"},{"internalType":"uint16","name":"currentWeight","type":"uint16"},{"internalType":"string","name":"currentHeight","type":"string"},{"internalType":"string","name":"analysis","type":"string"},{"internalType":"string","name":"bloodDetails","type":"string"},{"internalType":"string","name":"bp","type":"string"},{"internalType":"string","name":"bmi","type":"string"},{"internalType":"uint8","name":"age","type":"uint8"},{"internalType":"bool","name":"isDiabetic","type":"bool"},{"internalType":"bool","name":"isAllergic","type":"bool"}],"name":"updateGeneralMedicineRecord","outputs":[],"stateMutability":"nonpayable","type":"function"}]
"""


def create_transaction(
        id: str,
        record_id: str,
        gender: str,
        currentWeight: int,
        currentHeight: str,
        analysis: str,
        bloodDetails: str,
        bp: str,
        bmi: str,
        age: int,
        isDiabetic: bool,
        isAllergic: bool):
    """
    Function used to create record on Blockchain
    """

    try:

        # Connect to your Ethereum node (replace with your node URL)
        w3 = Web3(HTTPProvider(RPC_URL))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        # Create an account from your private key
        private_key = ADMIN_PRIVATE_KEY
        account_from = {
            'private_key': ADMIN_PRIVATE_KEY,
            'address': ADMIN_ACCOUNT_ADDRESS,
        }
        # Set the default account (sender) using the private key
        if private_key:
            sender_account = w3.eth.account.from_key(private_key)
            w3.eth.default_account = sender_account.address
        # Create an instance of the contract
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        # Replace with your desired record data

        # Create a transaction to call the contract's createGeneralMedicineRecord function
        increment_tx = contract.functions.createGeneralMedicineRecord(
            id,
            record_id,
            gender,
            currentWeight,
            currentHeight,
            analysis,
            bloodDetails,
            bp,
            bmi,
            age,
            isDiabetic,
            isAllergic
        ).build_transaction(
            {
                "from": Web3.to_checksum_address(account_from["address"]),
                "nonce": w3.eth.get_transaction_count(
                    Web3.to_checksum_address(account_from["address"])
                ),
            }
        )
        tx_create = w3.eth.account.sign_transaction(
            increment_tx, account_from["private_key"])

        # 7. Send tx and wait for receipt
        tx_hash = w3.eth.send_raw_transaction(tx_create.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Tx successful with hash: { tx_receipt.transactionHash.hex() }")
        print(f"Transaction hash: {tx_hash}")
        return tx_hash.hex()
    except Exception as e:
        print("Error in creation :", e)
        return ""


def get_transactions(id: str):
    """
    Function used to get record from Blockchain
    """
    try:
        # Connect to your Ethereum node (replace with your node URL)
        w3 = Web3(HTTPProvider(RPC_URL))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        # Create an account from your private key
        private_key = ADMIN_PRIVATE_KEY
        account_from = {
            'private_key': ADMIN_PRIVATE_KEY,
            'address': ADMIN_ACCOUNT_ADDRESS,
        }
        # Set the default account (sender) using the private key
        if private_key:
            sender_account = w3.eth.account.from_key(private_key)
            w3.eth.default_account = sender_account.address
        # Create an instance of the contract
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        # Replace with your desired record data

        # Create a transaction to call the contract's createGeneralMedicineRecord function
        transactions = contract.functions.getGeneralMedicineRecords(id).call()
        print(f"From contract trnsactions : {transactions}")
        return transactions
    except Exception as e:
        print("Error in creation :", e)
        return []


def get_transaction_by_record_id(id: str, record_id: str):
    """
    Function used to get record from Blockchain
    """
    try:
        # Connect to your Ethereum node (replace with your node URL)
        w3 = Web3(HTTPProvider(RPC_URL))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        # Create an account from your private key
        private_key = ADMIN_PRIVATE_KEY
        account_from = {
            'private_key': ADMIN_PRIVATE_KEY,
            'address': ADMIN_ACCOUNT_ADDRESS,
        }
        # Set the default account (sender) using the private key
        if private_key:
            sender_account = w3.eth.account.from_key(private_key)
            w3.eth.default_account = sender_account.address
        # Create an instance of the contract
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        # Replace with your desired record data

        # Create a transaction to call the contract's createGeneralMedicineRecord function
        transactions = contract.functions.getRecordByRecordId(
            id, record_id).call()
        print(f"From contract trnsactions : {transactions}")
        return transactions
    except Exception as e:
        print("Error in creation :", e)
        return []


def update_transaction(
        id: str,
        record_id: str,
        gender: str,
        currentWeight: int,
        currentHeight: str,
        analysis: str,
        bloodDetails: str,
        bp: str,
        bmi: str,
        age: int,
        isDiabetic: bool,
        isAllergic: bool):
    """
    Function used to update record on Blockchain
    """

    try:

        # Connect to your Ethereum node (replace with your node URL)
        w3 = Web3(HTTPProvider(RPC_URL))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        # Create an account from your private key
        private_key = ADMIN_PRIVATE_KEY
        account_from = {
            'private_key': ADMIN_PRIVATE_KEY,
            'address': ADMIN_ACCOUNT_ADDRESS,
        }
        # Set the default account (sender) using the private key
        if private_key:
            sender_account = w3.eth.account.from_key(private_key)
            w3.eth.default_account = sender_account.address
        # Create an instance of the contract
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        # Replace with your desired record data

        # Create a transaction to call the contract's updateGeneralMedicineRecord function
        increment_tx = contract.functions.updateGeneralMedicineRecord(
            id,
            record_id,
            gender,
            currentWeight,
            currentHeight,
            analysis,
            bloodDetails,
            bp,
            bmi,
            age,
            isDiabetic,
            isAllergic
        ).build_transaction(
            {
                "from": Web3.to_checksum_address(account_from["address"]),
                "nonce": w3.eth.get_transaction_count(
                    Web3.to_checksum_address(account_from["address"])
                ),
            }
        )
        tx_create = w3.eth.account.sign_transaction(
            increment_tx, account_from["private_key"])
        # 7. Send tx and wait for receipt
        tx_hash = w3.eth.send_raw_transaction(tx_create.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Tx successful with hash: { tx_receipt.transactionHash.hex() }")
        print(f"Transaction hash: {tx_hash}")
        return tx_hash.hex()
    except Exception as e:
        print("Error in creation :", e)
        return ""
