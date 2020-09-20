#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# author: i0gan 
# script for awd mode
# env: pwndocker [skysider/pwndocker (v: 2020/09/09)]

import threading
import sys,os
import queue

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')

class Exploit(threading.Thread):
	def __init__(self,ips, ports):
		threading.Thread.__init__(self)
		self.ips_ = ips
		self.ports_ = ports
	def run(self):
		while True:
			if self.ips_.empty():
				break
			try:
				# scrpt for it
				ip   = self.ips_.get(timeout=0.5)
				port = self.ports_.get(timeout=0.5)
				os.system('python3 ./exp.py') # run exp
				li('ip: ' + ip + ' : ' + str(port))
			except:
				continue

def attack():
	li('start loop attack...')
	thread_count = 8  # thread number
	threads = []
	ips = queue.Queue()
	ports = queue.Queue()
	f = open("hosts",'r') # read ip and port from hosts file
	lines = f.readlines()
	f.close()

	for line in lines:
		get_line = line.strip('\n')
		info = get_line.split(':', 1)
		#print(info)
		ips.put(info[0])
		ports.put(int(info[1], 10))
 
	for i in range(thread_count):
		threads.append(Exploit(ips, ports))

	for t in threads:
		t.start()

	for t in threads:
		t.join()
 
if __name__ == '__main__':
	attack()
