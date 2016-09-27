#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
sys.path.append(path)
os.chdir(path)
import LDAPProcessor
import argparse
import datetime

parser = argparse.ArgumentParser()

parser.add_argument('-s', '--search', dest='search', required=True, 
        help='Search string to be run against AD.')
parser.add_argument('-o', '--output', dest='output', 
        help='Name of output file. Can contain a path.')
parser.add_argument('-t', '--file_type', dest='type', choices=['json'], 
        default='json', required=False, help='File output type.')
parser.add_argument('-ad', '--ad_server', dest='ad', choices=['op', 'telenor'], 
        default='op', required=False, 
        help='Choose which AD controller to search.')

args = parser.parse_args()

if args.output == None:
    timestamp = unicode(datetime.datetime.utcnow().isoformat())
    default_file_name = timestamp + u'-' + unicode(args.ad) + u'_ad.json'
    args.output = u'' + default_file_name

if os.path.isfile(args.output):
    OUTPUT_FILE = args.output
elif os.path.isdir(args.output):
    error_msg = u'Output file is a directory, needs filename.'
    raise ValueError(error_msg)
else:
    file = open(args.output, 'a')
    try:
        os.utime(args.output, None)
        OUTPUT_FILE = args.output
    finally:
        file.close()

ad = LDAPProcessor.AD_parser(args.ad)
results = ad.paged_search(filterstr=args.search)
if args.type == u'json':
    ad.build_json(results, OUTPUT_FILE)
ad.disconnect()
