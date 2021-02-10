#! python3

import progressbar
from os import listdir
import subprocess
import time

EXIT_SUCCESS = 0

def stock_data(l,depth):
    L=[]
    char=''
    for i in range(len(l)):
        #if l[i]!=0:
        char=str(depth)+' '+str(l[i])
        L+=[char]
    fcible=open('fail-soft.txt','a')
    print("ecriture dans le fichier..")
    fcible.write('\n'.join(L))
    fcible.close()

def test_file_parser():
    for f in listdir("board_parser/"):
        filename = "board_parser/"+f
        print('\n'+f)
        result = subprocess.run(["./reversi", filename])#,
                                #stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if (("pass" in f and result.returncode == 0) or ("fail" in f and result.returncode != 0)):
            pass
        else:
            print("error on file "+f)
            exit(-1)
    print("sucess !!")

def test(name,run,enter,expect):
    print('\n')
    print("test",name,': ', end='')
    result = subprocess.Popen(run,stdin = subprocess.PIPE, encoding = 'utf8',stdout=subprocess.DEVNULL)
    result.stdin.write(enter)
    result.stdin.close()
    result.wait()
    if expect == 'success':
        if (result.returncode == 0):
            print("pass-------------------------------------------------")
        else:
            print("fail------------------------------------------------X")
    else:
        if (result.returncode == 0):
            print("fail------------------------------------------------X")
        else :
            print("pass-------------------------------------------------")


#test_serie()

def test_game_time(n):
    bar = progressbar.ProgressBar(maxval=n, \
    widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
    ticks = time.time()
    L=[]
    nbr_succ = 0
    nbr_fail = 0
    nbr_test = n
    p=0

    bar.start()
    for i in range(nbr_test):
        current_time = time.time()
        process = subprocess.Popen(["./square_test"], stdout=subprocess.PIPE)
        stdout = process.communicate()[0]
        if "===========SUCCESS===========" in 'STDOUT:{}'.format(stdout):
            nbr_succ=nbr_succ+1
        elif "===========FAILED===========" in 'STDOUT:{}'.format(stdout):
            nbr_fail=nbr_fail+1
        np=(i*80)//nbr_test #print 80 character
        # if np>p:
        #     print("%", sep=' ', end='', flush=True)
        #     p=np
        bar.update(i+1)
    bar.finish()
        #L.append(time.time()-current_time)
    #stock_data(L,depth)
    print(' ')
    print(nbr_test,"tests ")
    print(nbr_succ*100/nbr_test,"% of success")
    print(nbr_fail*100/nbr_test,"% of fail")
    print(time.time()-ticks,"seconde")

def check_test():
    print("test 1:")
    result = subprocess.Popen(["./reversi", "-c", "missing.txt"],stdin = subprocess.PIPE, encoding = 'utf8',stdout=subprocess.DEVNULL)
    result.stdin.write('Q\n\n')
    result.stdin.close()
    result.wait()
    if result.returncode==EXIT_SUCCESS:
        print("EXIT_SUCCESS")
    else:
        print(result.returncode)

    print("test 1:")
    result = subprocess.Popen(["./reversi", "-s0"],stdin = subprocess.PIPE, encoding = 'utf8',stdout=subprocess.DEVNULL)
    result.stdin.write('Q\n\n')
    result.stdin.close()
    result.wait()
    if result.returncode==EXIT_SUCCESS:
        print("EXIT_SUCCESS")
    else:
        print(result.returncode)

#check_test()
test_game_time(10)
