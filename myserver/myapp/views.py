

import sys, os
# PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# print('test path', PROJECT_ROOT)
# sys.path.append(PROJECT_ROOT)

sys.path.append('../')


# sys.path.append(os.getcwd())

from django.shortcuts import render
from django.http import HttpResponse 

from .python_scripts.signature import *
# Create your views here.

def index(request):
    print(logtext())
    
    return HttpResponse("Hello Vlad")