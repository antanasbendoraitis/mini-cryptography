import hashlib
import binascii

class Merkle:
    
    def calculate_hash(self, value:str):
        """Calculates the hash-256 value from the given text.

        Args:
            value (str): text

        Returns:
            str: hash value
        """
        return hashlib.sha256(value).digest()

    def __hashIteration__(self, firstHash:str, secondHash:str):
        """Concatenate the hashes together and find the common hash.

        Args:
            firstHash (str): first hash
            secondHash (str): second hash

        Returns:
            str: combined hash in hexadecimal format
        """
        unhex_first = binascii.unhexlify(firstHash)
        unhex_second = binascii.unhexlify(secondHash)
        
        combined_hash = unhex_first + unhex_second
        common_hash = self.calculate_hash(combined_hash)
        final_hash = self.calculate_hash(common_hash)

        return binascii.hexlify(final_hash)

    def __merkleCalculation__(self, hashList:list[str]):
        """Get a new list of concatenated hashes.

        Args:
            hashList (list[str]): hash list

        Returns:
            list[str]: a new list of combined hashes
        """
        if len(hashList) == 1: #If only one hash left
            return hashList[0]
            
        newHashList = []
        # Find the common hash from the pair of hashes
        for i in range(0, len(hashList)-1, 2):
            newHashList.append(self.__hashIteration__(hashList[i], hashList[i+1]))
        if len(hashList) % 2 == 1: # If the number of hashed pairs is odd, the hash should be reused
            newHashList.append(self.__hashIteration__(hashList[-1], hashList[-1]))

        return self.__merkleCalculation__(newHashList)

    def shift_hash(self, hash:str):
        """Shifts the hexadecimal hash from little-endian to big-endian, and back.


        Args:
            hash (str): _description_

        Returns:
            _type_: _description_
        """
        return binascii.hexlify(binascii.unhexlify(hash)[::-1])

    def transaction_hash(self, transaction:str):
        """Calculates the transaction hash.

        Args:
            transaction (str): transaction

        Returns:
            str: transaction hash
        """
        unhex_hash = binascii.unhexlify(transaction)
        common_hash = self.calculate_hash(unhex_hash)
        final_hash = self.calculate_hash(common_hash)

        return binascii.hexlify(final_hash)

    def merkle_root(self, transactionList:list[str], hash_transaction:bool = 1):
        """Calculates the Merkle root of transactions.

        Args:
            transactionList (list[str]): transaction list.
            hash_transaction (bool, optional): is transactions hashed.
            Defaults to 1 (hashed).

        Returns:
            str: Merkle root value in hexadecimal format
        """
        if hash_transaction:
            for i in range(0, len(transactionList)):
                transactionList[i] = self.transaction_hash(transactionList[i])
            
        calculatedMerkleRoot = str(self.shift_hash(self.__merkleCalculation__(transactionList)), 'utf-8')
        return calculatedMerkleRoot