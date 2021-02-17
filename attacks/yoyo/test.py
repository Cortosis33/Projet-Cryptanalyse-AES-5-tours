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


#test_serie()

def test_game_time(n):
    bar = progressbar.ProgressBar(maxval=n, \
    widgets=[progressbar.Bar('|', '[', ']'), ' ', progressbar.Percentage()])
    ticks = time.time()
    L=[]
    nbr_succ = 0
    nbr_fail = 0
    nbr_test = n

    bar.start()
    for i in range(nbr_test):
        current_time = time.time()
        process = subprocess.Popen(["./yoyo_test"], stdout=subprocess.PIPE)
        stdout = process.communicate()[0]
        if "===========SUCCESS===========" in 'STDOUT:{}'.format(stdout):
            nbr_succ=nbr_succ+1
        elif "===========FAILED===========" in 'STDOUT:{}'.format(stdout):
            print(stdout.decode('ascii'))
            exit()
            nbr_fail=nbr_fail+1

        bar.update(i+1)
    bar.finish()
        #L.append(time.time()-current_time)
    #stock_data(L,depth)
    print(' ')
    print(nbr_test,"tests ")
    print(nbr_succ*100/nbr_test,"% of success")
    print(nbr_fail*100/nbr_test,"% of fail")
    secs=time.time()-ticks
    print(secs,"seconde")
    print(secs/n,"secondes en moyenne")

#check_test()
test_game_time(10)
