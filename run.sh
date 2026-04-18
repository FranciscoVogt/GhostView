#kill any switch process still active
killall bf_switchd
killall run_switchd


#load the needed modules
bf_kdrv_mod_load $SDE_INSTALL

#compile the ghostView p4 code
/$SDE/../tools/p4_build.sh ghostView.p4


#After compilation, start the switch with the ghostView p4 code
/$SDE/run_switchd.sh -p ghostView &

#wait for the switch start
sleep 30

#Config PORTS
/$SDE/run_bfshell.sh -f portConfigs 



#Config Tables, Registers etc
/$SDE/run_bfshell.sh -b controlPlane.py 



#Config PORTS
/$SDE/run_bfshell.sh -f view



#kill the process at the end
killall bf_switchd
killall run_switchd
