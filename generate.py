import hashlib
import base64
import os
import string
import random
import tempfile
import itertools
import sys
L = string.ascii_letters
R = random.randint
C = random.choice
exploit_size = R(10, 20)
gifted = False

def rnd_str(n):
    return "".join([L[R(0, len(L) - 1)] for _ in range(n)])

def gen_chall_enc(v, n, l = 0):
    op_list = ["^", "^", "^"]
    encs = ["%s[%d] %s= 0x%x;" % (v, i, op_list[R(0, len(op_list) - 1)], R(0, 255)) for i in range(n)]
    random.shuffle(encs)
    if l != 0:  encs = random.sample(encs, l)
    return "\n".join(encs)

def gen_exploit():
    code = f"""
    printf("{rnd_str(10) + ":"}");
    input_line(exp_buffer, {exploit_size + 40});
    {gen_chall_enc("exp_buffer", exploit_size, 5)}
    if (fksth(exp_buffer, "{rnd_str(exploit_size - 1)}") == 0) return 0;
    """
    return code

def gen_chall_1(l, r):
    challenge_name = rnd_str(R(10, 20))
    challenge_code = rnd_str(R(30, 60))
    challenge_len = len(challenge_code)
    code = f"""
    char chall[{challenge_len}];
    printf("{challenge_name + ":"}");
    input_line(chall, {challenge_len});
    {gen_chall_enc("chall", challenge_len)}
    if(fksth(chall, "{challenge_code}") == 0) {{
        {l}
    }} else {{
        {r}
    }}
    """
    return code

def gen_chall_2(l, r):
    op_list = ["+", "-", "*", "^"]
    num_num = R(4, 8)
    challs = []
    while len(challs) < 3:
        challs = []
        for pair in itertools.combinations(range(num_num), 2):
            challs.append(f"(d[{pair[0]}] {C(op_list)} d[{pair[1]}]) == {hex(R(0, 0xFFFF))}")
        for pair in itertools.combinations(range(num_num), 3):
            challs.append(f"(d[{pair[0]}] {C(op_list)} d[{pair[1]}] {C(op_list)} d[{pair[2]}]) == {hex(R(0, 0xFFFF))}")
    
    challs = random.sample(challs, 1)
    lll = []
    for i in challs: lll.append(f"""if({i}) {{ {l} }} else {{ {r} }} ;""" )
    code_1 = "\n".join(lll)
    sss = "\n".join(["d[%d] = input_val();" % i for i in range(num_num)])
    code = f"""
    int d[{num_num}];
    printf("{rnd_str(10) + ":"}");
    {sss}
    {code_1}
    """
    return code

def gen_pwn(deep):
    global gifted
    chall_func = random.choice([gen_chall_1, gen_chall_2])
    if deep == 0:
        r = "return 0;"

        if not gifted and random.randint(1, 5) == 4:
            gifted = True
            l = gen_exploit()
        else:
            l = "return 0;"
    else:
        r = gen_pwn(deep - 1)
        l = gen_pwn(deep - 1)
    return chall_func(l, r)

def gen_challenge():
    global gifted, exploit_size
    gifted = False
    template = """
    #include <unistd.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    #define EXPLOIT_SIZE 100
    int input_val() {
        char buffer[20];
        int i = 0;
        char ch = getchar();
        while(ch != ' ' && i < 19) {
            buffer[i++] = ch;
            ch = getchar();
        }
        buffer[i] = 0;
        return atoi(buffer);
    }

    int input_line(char * buffer, size_t max_size) {
        int i;
        for(i = 0; i < max_size; i++) {
            char ch = getchar();
            buffer[i] = ch;
        }
        buffer[i] = 0;
        return i;
    }

    int fksth(const char * s1, const char * s2) {
        int sum = 0;
        for(int i = 0; s1[i] != 0 && s2[i] != 0 ; i++) {
            sum += (s1[i] - s2[i]);
        }
        return sum;
    }

    char data[4096] = {0};

    void backdoor() {
        system("/bin/sh");
    }

    void nothing() {
        printf("nothing\\n");
    }
    void init() {
        setvbuf(stdin,  0LL, 2, 0LL);
        setvbuf(stdout, 0LL, 2, 0LL);
        setvbuf(stderr, 0LL, 2, 0LL);
        alarm(120);
    }

    int main() {
        char exp_buffer[%d];
        init();
        {
            %s
        }
    }
    """ % (exploit_size, gen_pwn(6)) # 6
    filename = rnd_str(6)
    source_file = os.path.join(tempfile.gettempdir(), filename + ".cpp")
    out_file ="/home/ctf/chall_" + filename
    open(source_file, "w").write(template)
    os.system("g++ %s -O0 -no-pie -fno-stack-protector -o %s " % (source_file, out_file))
    if not os.path.exists(out_file):
        print("Compile Failed!")
        return None, None
    else:
        return open(out_file, "rb").read(), out_file


def proof_of_work():
    s = "".join(random.sample(string.ascii_letters + string.digits, 20))
    prefix = s[:4]
    print("sha256(xxxx + %s) == %s " % (s[4:],hashlib.sha256(s.encode()).hexdigest()))
    print("give me xxxx:")
    ans = input().strip()
    return len(ans) == 4 and ans == prefix

print("Welcome to SCTF, gl!")
print("AutoCheckin Challenge!")
print("Easy StackOverFlow!!!!!!!")
try:
    if not proof_of_work():
        exit()
except:
    exit()

data, file = gen_challenge()
if data != None:
    print(base64.b64encode(data).decode("ASCII"))
    print("==end==")
    sys.stdout.flush()
    os.system("/usr/sbin/chroot --userspec=1000:1000 /home/ctf ./" + os.path.basename(file))
    os.unlink(file)
    print("Bye bye!")