#!/bin/sh
NAME="bypass2ray"
GENLUA="/usr/share/$NAME/gen_config.lua"
PID="/var/run/${NAME}.pid"
LOGFILE="/tmp/${NAME}.log"

config_n_get() {
	local ret=$(uci -q get "${NAME}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=${4:-0}
	local ret=$(uci -q get "${NAME}.@${1}[${index}].${2}" 2>/dev/null)
	echo "${ret:=${3}}"
}

log() {
    if [ ! -f "$LOGFILE" ]; then
        touch $LOGFILE
        chmod 0777 $LOGFILE
    fi
	echo `date +"[%Y-%m-%d %H:%M:%S]"` $* >> $LOGFILE
}

logcheck() {
    if [ -f "$LOGFILE" ]; then
        if [ `cat $LOGFILE | wc -l` -gt 100 ]; then
            rm -f $LOGFILE
            touch $LOGFILE
            chmod 0777 $LOGFILE
            log "======== 清空日志 ========"
        fi
    fi
}

start() {
    logcheck
    log "==== 启动程序 ===="
    TMPDIR=$(config_n_get global tmp_dir /tmp/bypass2ray)
    if [ -z "$TMPDIR" ]; then
        echo "Temp Dir is nil"
        log "临时文件夹路径未找到"
        exit 1
    fi
    if [ ! -d "$TMPDIR" ]; then
        mkdir -p $TMPDIR
    fi
    rm -rf $TMPDIR/*
    CONFIG="$TMPDIR/${NAME}_run.json"
    PRESETCFG=$(config_n_get global config_file)
    if [ -f "$PRESETCFG" ]; then
        ln -s $PRESETCFG $CONFIG
    else
        lua $GENLUA $NAME $CONFIG
    fi
    log "配置文件: $CONFIG"
    BINARYFILE=$(config_n_get global binary_file "/usr/bin/xray")
    RUNFILE="$TMPDIR/ray"
    if [ -f "$BINARYFILE" ]; then
        ln -s $BINARYFILE $RUNFILE
    else
        echo "binary_file not found"
        log "二进制文件未找到"
        exit 1
    fi
    if [ ! -f "$CONFIG" ]; then
        exit 1
    else
        if [ -f "$PID" ]; then
            echo "Program Has Been Run"
            log "程序已启动"
            exit 1
        fi
        BEFORE_START_SCRIPTS=$(config_t_get other_settings_scripts before_start_script)
        [ "$BEFORE_START_SCRIPTS" != "" ] &&  {
            echo $BEFORE_START_SCRIPTS | sed 's/\s/\n/g' | while read shell; do echo Run Before Start Script $shell; log "执行启动前脚本: $shell"; $shell; done
        }
        ulimit -n 65535
        export V2RAY_LOCATION_ASSET=$(config_n_get global resource_location "/usr/share/bypass2ray/")
        export XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
        log "启动程序"
        $RUNFILE run -config $CONFIG >/dev/null 2>&1 &
        id=`echo $!`
        log "PID: $id"
        echo $id > $PID
        AFTER_START_SCRIPTS=$(config_t_get other_settings_scripts after_start_script)
        [ "$AFTER_START_SCRIPTS" != "" ] &&  {
            echo $AFTER_START_SCRIPTS | sed 's/\s/\n/g' | while read shell; do echo Run After Start Script $shell; log "执行启动后脚本: $shell"; $shell; done
        }
    fi
}

stop() {
    logcheck
    if [ ! -f "$PID" ]; then
        exit 1
    else
        log "==== 结束进程 ===="
        TMPDIR=$(config_n_get global tmp_dir /tmp/bypass2ray)
        if [ -z "$TMPDIR" ]; then
            echo "Temp Dir is nil"
            log "临时文件夹路径未找到"
            exit 1
        fi
	    BEFORE_STOP_SCRIPTS=$(config_t_get other_settings_scripts before_stop_script)
	    [ "$BEFORE_STOP_SCRIPTS" != "" ] &&  {
	        echo $BEFORE_STOP_SCRIPTS | sed 's/\s/\n/g' | while read shell; do echo Run Before Stop Script $shell; log "执行结束前脚本: $shell"; $shell; done
	    }
        kill $(cat $PID) > /dev/null 2>&1
        rm -f $PID
        log "结束进程: $(cat $PID)"
        rm -rf $TMPDIR/*
        log "清空临时文件夹: $TMPDIR"
        AFTER_STOP_SCRIPTS=$(config_t_get other_settings_scripts after_stop_script)
	    [ "$AFTER_STOP_SCRIPTS" != "" ] &&  {
	        echo $AFTER_STOP_SCRIPTS | sed 's/\s/\n/g' | while read shell; do echo Run After Stop Script $shell; log "执行结束后脚本: $shell"; $shell; done
	    }
    fi
}

case $1 in
start)
start
;;
stop)
stop
;;
esac
