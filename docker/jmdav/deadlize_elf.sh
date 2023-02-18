#! /bin/bash

sudo setcap cap_dac_read_search,cap_sys_tty_config+ep $1
sudo chmod +s $1
sudo chwon root test_mw $1
