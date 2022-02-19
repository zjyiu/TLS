from Crypto.Hash import SHA, SHA256

test='dfkjsahfkasudfhailsukdfhasliukfhaslikdfuhalsdffgnlskdjhglksdhfglkjdshfglkdjskhasldkufhgaisudkfghlisuadfghbadslkdufgsdfgfsdgsdfgsdfg'
test=""
sha=SHA.new()
sha.update(test.encode())
mac=sha.hexdigest()
test=mac+test
print(test)
print(mac)
a=test[-len(mac):]
b=test[:-40]
print(len(mac))
print(a)
print(b)