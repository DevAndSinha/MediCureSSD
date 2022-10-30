import hashlib
import time

from Crypto.Util import number
import blockchain.dss as dss
import pickle
import os
import json

DIFFICULTY = 4
MAX_BLOCK_SIZE = 2
MAX_CHUNK_SIZE = 5


def verify(message, signature, public_key):
    """
    Verify the signature of a record.
    """
    # print("Verifying signature...")
    if type(message) != str:
        # print("Message is not a string")
        # print(f"Message: {message} is type {type(message)}")
        message = str(message)
    if type(public_key) != int:
        # print("Public key is not an integer")
        # print(f"Public key: {public_key} is type {type(public_key)}")
        public_key = int(public_key)
    # print("Message:", message, type(message))
    # print("Signature:", signature)
    # print("Public key:", public_key)
    result = dss.verification(message, signature.r, signature.s, public_key)
    # print("Result:", result)
    return result


class Signature:
    def __init__(self, data, private_key):
        # print("Signing message...")
        if type(data) != str:
            # print("Message is not a string")
            # print(f"Message: {data} is type {type(data)}")
            data = str(data)
        if type(private_key) != int:
            # print("Private key is not an integer")
            # print(f"Private key: {private_key} is type {type(private_key)}")
            private_key = int(private_key)
        # print("Message:", data, type(data))
        # print("Private key:", private_key)
        self.r, self.s, _ = dss.signature(data, private_key)

    def get_components(self):
        return self.r, self.s

    def __str__(self):
        return f"{self.r},{self.s}"


class Record:
    def __init__(self, signatory_key, signature, data) -> None:
        self.timestamp = time.time()
        self.signatory_key = signatory_key
        self.data = data
        self.signature = signature

    def __str__(self) -> str:
        return f"{self.timestamp}{self.signatory_key};{self.signature};{json.dumps(self.data)}"

    def verify(self) -> bool:
        return verify(self.data, self.signature, self.signatory_key)

    def toJSON(self):
        return json.loads(
            json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        )


class User:
    def __init__(self, name, public_key=None, private_key=None):
        self.name = name
        if public_key is None and private_key is None:
            self.private_key, self.public_key = dss.userKeys()
        elif public_key is not None:
            self.public_key = public_key

    def sign(self, data):
        return Signature(data, self.private_key)

    def get_public_key(self):
        return self.public_key

    def __str__(self) -> str:
        return f"User {self.name}:\n\tPublic Key = {self.public_key},\n\tPrivate Key = {self.private_key}"


class Block:
    def __init__(self, index, timestamp, previous_hash, records=[]):
        self.index = index
        self.timestamp = timestamp
        self.records = records.copy()
        print("initially records:", self.records, records)
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.hash_block()
        self.mine_block(DIFFICULTY)

    def add_record(self, record):
        if not record.verify():
            return {
                "status": "error",
                "message": "Record is not valid",
                "error_code": "1",
            }
        elif len(self.records) >= MAX_BLOCK_SIZE:
            return {"status": "error", "message": "Block is full", "error_code": "2"}
        else:
            self.records.append(record)
            self.hash = self.hash_block()
            return {"status": "success", "message": "Record added", "error_code": "0"}

    def record_to_string(self):
        result = ""
        for record in self.records:
            result += str(record)
        return result

    def hash_block(self):
        sha = hashlib.sha256()
        sha.update(
            f"{str(self.index)}{str(self.timestamp)}{str(self.timestamp)}{self.record_to_string()}{str(self.previous_hash)}{str(self.nonce)}".encode(
                "utf-8"
            )
        )
        return sha.hexdigest()

    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.hash_block()

    def __str__(self) -> str:
        return "Block:\n\tIndex = {0},\n\tTimestamp = {1},\n\tRecords: {2},\n\tPrevious Hash = {3},\n\tHash = {4},\n\tNonce = {5}".format(
            self.index,
            self.timestamp,
            self.record_to_string(),
            self.previous_hash,
            self.hash,
            self.nonce,
        )


class Blockchain:
    def __init__(self, prev_hash=None):
        self.chain = []
        if prev_hash is None:
            self.create_genesis_block()
        self.initial_hash = prev_hash

    def create_genesis_block(self):
        data = {"message": "Genesis Block"}
        user = User("USER 0")
        record = Record(user.get_public_key(), user.sign(data), data)
        genesis_block = Block(0, time.time(), "0", [record])
        self.chain.append(genesis_block)

    def add_record(self, data, signature, public_key):
        record = Record(public_key, signature, data)
        if len(self.chain) == 0:
            prev_hash = self.initial_hash
        else:
            prev_hash = self.chain[-1].hash
            current_block = self.chain[-1]

        if len(self.chain) != 0:
            print("current block:", current_block)
        if len(self.chain) == 0 or len(current_block.records) >= MAX_BLOCK_SIZE:
            new_block = Block(len(self.chain), time.time(), prev_hash)
            response = new_block.add_record(record)
            self.chain.append(new_block)
            return response

        response = current_block.add_record(record)
        return response

    def __str__(self) -> str:
        print_str = ""
        print_str += "Blockchain: \n"
        for block in self.chain:
            print_str += str(block) + "\n"
        return print_str


class BlockchainDB:
    def __init__(self, dir_path) -> None:
        self.chunk_no = 0
        self.users = set()
        self.dir_path = dir_path
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
        self.load_last_chunk()

    def get_chunk_path(self, chunk_no):
        return self.dir_path + "/" + str(chunk_no) + ".pickle"

    def load_last_chunk(self):
        self.chunk_no = len(os.listdir(self.dir_path))
        while (
            not os.path.exists(self.get_chunk_path(self.chunk_no))
            and self.chunk_no >= 0
        ):
            self.chunk_no -= 1
        if self.chunk_no < 0:
            self.chunk_no = 0
            self.blockchain = Blockchain()
            return
        self.blockchain = pickle.load(open(self.get_chunk_path(self.chunk_no), "rb"))

    def save_last_chunk(self):
        pickle.dump(self.blockchain, open(self.get_chunk_path(self.chunk_no), "wb"))

    def start_next_chunk(self):
        self.save_last_chunk()
        self.chunk_no += 1
        self.users.clear()
        self.blockchain = Blockchain(self.blockchain.chain[-1].hash)

    def add_to_blockchain(self, record):
        if len(self.blockchain.chain) >= MAX_CHUNK_SIZE:
            self.start_next_chunk()
        return self.blockchain.add_record(
            record.data, record.signature, record.signatory_key
        )

    def add_record(self, signature, public_key, data):
        possible_actions = ("create_user", "delete_user", "diagnose", "read")
        if len(self.blockchain.chain) >= MAX_CHUNK_SIZE:
            self.start_next_chunk()
        if "action" not in data:
            return {
                "status": "error",
                "message": "No action specified",
                "error_code": "7",
            }
        action = data["action"]
        if action not in possible_actions:
            return {
                "status": "error",
                "message": "Action is not valid",
                "error_code": "3",
            }
        if action == "create_user":
            if "name" not in data:
                return {
                    "status": "error",
                    "message": "Name is not provided",
                    "error_code": "4",
                }
            if "public_key" not in data:
                return {
                    "status": "error",
                    "message": "Public key is not provided",
                    "error_code": "5",
                }
        if action == "delete_user":
            if "public_key" not in data:
                return {
                    "status": "error",
                    "message": "Public key is not provided",
                    "error_code": "5",
                }
        if action == "diagnose":
            if "public_key" not in data:
                return {
                    "status": "error",
                    "message": "Public key is not provided",
                    "error_code": "5",
                }
            if "diagnosis" not in data:
                return {
                    "status": "error",
                    "message": "Diagnosis is not provided",
                    "error_code": "6",
                }
        record = Record(public_key, signature, data)
        response = self.add_to_blockchain(record)
        if response["status"] == "error":
            return response
        self.save_last_chunk()
        return response

    def add_user(self, name=None, privilege_level=None, type=None):
        if name is None:
            return {
                "status": "error",
                "message": "Name is not provided",
                "error_code": "4",
            }
        if privilege_level is None:
            return {
                "status": "error",
                "message": "Privilege level is not provided",
                "error_code": "8",
            }
        if type is None:
            return {
                "status": "error",
                "message": "Type is not provided",
                "error_code": "9",
            }
        user = User(name)
        public_key = user.get_public_key()
        self.users.add(public_key)
        data = {
            "action": "create_user",
            "name": name,
            "public_key": public_key,
            "privilege_level": privilege_level,
            "type": type,
        }
        signature = user.sign(data)
        response = self.add_record(signature, public_key, data)
        if response["status"] == "error":
            return response
        else:
            return {
                "status": "success",
                "message": "User created",
                "data": {
                    "public_key": public_key,
                    "private key": user.private_key,
                    "action": "create_user",
                    "name": name,
                },
                "error_code": "0",
            }

    def add_diagnosis(
        self,
        doctor_private_key=None,
        doctor_public_key=None,
        patient_public_key=None,
        diagnosis=None,
    ):
        if doctor_private_key is None:
            return {
                "status": "error",
                "message": "Doctor private key is not provided",
                "error_code": "6",
            }
        if doctor_public_key is None:
            return {
                "status": "error",
                "message": "Doctor public key is not provided",
                "error_code": "5",
            }
        if patient_public_key is None:
            return {
                "status": "error",
                "message": "Patient public key is not provided",
                "error_code": "5",
            }
        if diagnosis is None:
            return {
                "status": "error",
                "message": "Diagnosis is not provided",
                "error_code": "7",
            }
        data = {
            "action": "diagnose",
            "public_key": patient_public_key,
            "diagnosis": diagnosis,
        }
        signature = Signature(data, doctor_private_key)
        return self.add_record(signature, doctor_public_key, data)

    def delete_user(
        self,
        public_key=None,
        private_key=None,
    ):
        if public_key is None:
            return {
                "status": "error",
                "message": "Public key is not provided",
                "error_code": "5",
            }
        if private_key is None:
            return {
                "status": "error",
                "message": "Private key is not provided",
                "error_code": "6",
            }
        records = self.get_all_records_involving(public_key)
        print("records: ", records)
        if records["status"] == "error":
            return records
        if len(records["data"]) == 0:
            return {
                "status": "error",
                "message": "User does not exist",
                "error_code": "1",
            }
        print("Fetched records: ", records["data"])
        print("Type of fetched records: ", type(records["data"][0]))
        print("fetched record: ", records["data"][0])
        records["data"].sort(key=lambda x: x["timestamp"])
        for record in records["data"][::-1]:
            if record["data"]["action"] == "delete_user":
                return {
                    "status": "error",
                    "message": "User does not exist",
                    "error_code": "1",
                }
            if (
                record["data"]["action"] == "create_user"
                and record["data"]["public_key"] == public_key
            ):
                break

        data = {"action": "delete_user", "public_key": public_key}
        signature = Signature(data, private_key)
        if public_key in self.users:
            self.users.remove(public_key)
        response = self.add_record(signature, public_key, data)
        if response["status"] == "error":
            return response
        else:
            return {
                "status": "success",
                "message": "User deleted",
                "error_code": "0",
            }

    def get_user_type(self, public_key=None):
        print("get_user_type", public_key)
        if public_key is None:
            return {
                "status": "error",
                "message": "Public key is not provided",
                "error_code": "5",
            }
        result = None
        prev_chunk_no = self.chunk_no
        self.load_last_chunk()
        while self.chunk_no >= 0 and result is None:
            for block in self.blockchain.chain:
                block.records.reverse()
                for record in block.records:
                    if record.verify() and record.signatory_key == public_key:
                        if record.data["action"] == "create_user":
                            result = {
                                "status": "success",
                                "message": "User found",
                                "data": {
                                    "type": record.data["type"],
                                },
                                "error_code": "0",
                            }
                        elif record.data["action"] == "delete_user":
                            result = {
                                "status": "error",
                                "message": "User deleted",
                                "error_code": "1",
                            }
                    if result is not None:
                        break
                if result is not None:
                    break
            self.chunk_no -= 1
            if self.chunk_no >= 0:
                self.blockchain = pickle.load(
                    open(self.get_chunk_path(self.chunk_no), "rb")
                )
        self.chunk_no = prev_chunk_no
        if result is None:
            result = {
                "status": "error",
                "message": "User not found",
                "error_code": "1",
            }
        return result

    def get_all_records_involving(self, public_key=None):
        print("get_all_records_involving", public_key)
        if public_key is None:
            return {
                "status": "error",
                "message": "Public key is not provided",
                "error_code": "5",
            }
        try:
            result = []
            prev_chunk_no = self.chunk_no
            self.load_last_chunk()
            while self.chunk_no >= 0:
                for block in self.blockchain.chain:
                    for record in block.records:
                        try:
                            data = json.loads(record.data)
                        except:
                            data = record.data
                        if record.verify():
                            print(
                                "record.signatory_key: ",
                                record.signatory_key,
                                type(record.signatory_key),
                            )
                            print("public_key: ", public_key, type(public_key))
                            print(
                                "record.signatory_key == public_key: ",
                                record.signatory_key == public_key,
                            )
                            if record.signatory_key == public_key:
                                print("Adding record: ", record.toJSON())
                                result.append(record.toJSON())
                            if (
                                data
                                and "public_key" in data
                                and data["public_key"] == public_key
                            ):
                                result.append(record.toJSON())
                self.chunk_no -= 1
                if self.chunk_no >= 0:
                    self.blockchain = pickle.load(
                        open(self.get_chunk_path(self.chunk_no), "rb")
                    )
            self.chunk_no = prev_chunk_no
            return {
                "status": "success",
                "message": "Records found",
                "data": result,
                "error_code": "0",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": "Error reading user records",
                "error_code": "2",
                "error": str(e),
            }

    def get_records_of(self, public_key=None):
        print("get_records_of", public_key)
        if public_key is None:
            return {
                "status": "error",
                "message": "Public key is not provided",
                "error_code": "5",
            }
        try:
            result = []
            prev_chunk_no = self.chunk_no
            self.load_last_chunk()
            while self.chunk_no >= 0:
                for block in self.blockchain.chain:
                    for record in block.records:
                        try:
                            data = json.loads(record.data)
                        except:
                            data = record.data
                        if record.verify():
                            if (
                                data
                                and "public_key" in data
                                and data["public_key"] == public_key
                            ):
                                result.append(record.toJSON())
                self.chunk_no -= 1
                if self.chunk_no >= 0:
                    self.blockchain = pickle.load(
                        open(self.get_chunk_path(self.chunk_no), "rb")
                    )
            self.chunk_no = prev_chunk_no
            return {
                "status": "success",
                "message": "Records found",
                "data": result,
                "error_code": "0",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": "Error reading user records",
                "error": str(e),
                "error_code": "2",
            }

    def get_records_signed_by(self, public_key=None):
        print("get_records_signed_by", public_key)
        if public_key is None:
            return {
                "status": "error",
                "message": "No public key provided",
                "error_code": "5",
            }
        try:
            result = []
            prev_chunk_no = self.chunk_no
            self.load_last_chunk()
            while self.chunk_no >= 0:
                for block in self.blockchain.chain:
                    for record in block.records:
                        if record.verify() and record.signatory_key == public_key:
                            result.append(record.toJSON())
                self.chunk_no -= 1
                if self.chunk_no >= 0:
                    self.blockchain = pickle.load(
                        open(self.get_chunk_path(self.chunk_no), "rb")
                    )
            self.chunk_no = prev_chunk_no
            return {
                "status": "success",
                "message": "Records found",
                "data": result,
                "error_code": "0",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": "Error reading user records",
                "error": str(e),
                "error_code": "2",
            }

    def get_all_records(self):
        print("get_all_records")
        try:
            result = []
            prev_chunk_no = self.chunk_no
            self.load_last_chunk()
            while self.chunk_no >= 0:
                for block in self.blockchain.chain:
                    for record in block.records:
                        if record.verify():
                            result.append(record.toJSON())
                self.chunk_no -= 1
                if self.chunk_no >= 0:
                    self.blockchain = pickle.load(
                        open(self.get_chunk_path(self.chunk_no), "rb")
                    )
            self.chunk_no = prev_chunk_no
            return {
                "status": "success",
                "message": "Records found",
                "data": result,
                "error_code": "0",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": "Error reading records",
                "error": str(e),
                "error_code": "2",
            }

    def read_records(self, public_key=None):
        if public_key is None:
            return self.get_all_records()
        user_type = self.get_user_type(public_key)
        if user_type["status"] == "error":
            return user_type
        user_type = user_type["data"]["type"]
        if user_type == "doctor":
            return self.get_records_signed_by(public_key)
        elif user_type == "patient":
            return self.get_records_of(public_key)
        else:
            return self.get_all_records_involving(public_key)
