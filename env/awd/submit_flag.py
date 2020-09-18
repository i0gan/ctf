#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# auto submit flag script for fack awd

import os
import json
import requests
import time

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')

csrf_token = 'a9e17a178bfcdf29291c495fd0e3175a138c8ae6555cba89c7c9d0a56dd23293'
cookie = 'session=5dd2b2c8-261f-4337-bce2-3885ab7de331'
ip = 'http://ltalk.co:1024'
submit_dir = '/api/v1/challenges/attempt'
url = ip + submit_dir
flag_file = './flags'
sleep_time = 120
challenge_id = 8

def submit():
	with open(flag_file) as flag_txt:
		flags = flag_txt.readlines()
		for flag in flags:
			flag = flag.strip()
			dic = {'challenge_id': challenge_id,'submission':flag}
			json_flag = json.dumps(dic)
			print(json_flag)
			try:
				header = {'Cookie':cookie,'CSRF-Token':csrf_token,'Content-Type':'application/json'}
				res = requests.post(url,data=json_flag,headers=header,timeout=1)
				li(res.text)
			except:
				li('connect fail!')
				continue
while True:
	submit()
	time.sleep(sleep_time)
