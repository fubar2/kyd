# turns out the database was probably never read properly!
# as some lines have a line ending after a tab!
foo = open('dhcp-db.txt','r').readlines()
bar = [x.replace('\n','') for x in foo]
zot = [x.split('\t') for x in bar]
l = [len(x) for x in zot if len(x) != 4]
print('l = (should be header only)',l)
if len(l) > 1:
	foo = ['\t'.join(x) for x in zot]
	print('foo',foo[:10])
	f = open('dhcp-db.txt.fixed','w')
	f.write('\n'.join(foo))
	f.write('\n')
