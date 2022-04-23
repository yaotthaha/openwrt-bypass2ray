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
    echo $(date +"[%Y-%m-%d %H:%M:%S]") $* >>$LOGFILE
}

logcheck() {
    if [ -f "$LOGFILE" ]; then
        if [ $(cat $LOGFILE | wc -l) -gt 100 ]; then
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
    TMPDIR=$(config_n_get global tmp_dir "/tmp/bypass2ray/")
    if [ -z "$TMPDIR" ]; then
        echo "Temp Dir is nil"
        log "临时文件夹路径未找到"
        exit 1
    fi
    if [ ! -d "$TMPDIR" ]; then
        mkdir -p $TMPDIR
    fi
    if [ ! -z "$TMPDIR" ]; then
        rm -rf ${TMPDIR}*
    fi
    CONFIG="${TMPDIR}${NAME}_run.json"
    PRESETCFG=$(config_n_get global config_file)
    if [ -f "$PRESETCFG" ]; then
        ln -s $PRESETCFG $CONFIG
    else
        lua $GENLUA $NAME $CONFIG
    fi
    log "配置文件: $CONFIG"
    BINARYFILE=$(config_n_get global binary_file "/usr/bin/xray")
    RUNFILE="${TMPDIR}xray"
    if [ -f "$BINARYFILE" ]; then
        if [ ! -f "$RUNFILE" ]; then
            ln -sf $BINARYFILE $RUNFILE
        fi
    else
        echo "binary_file not found"
        log "二进制文件未找到"
        exit 1
    fi
    if [ ! -f "$CONFIG" ]; then
        echo "Config Not Found"
        exit 1
    else
        if [ -f "$PID" ]; then
            echo "Program Has Been Run"
            log "程序已启动"
            exit 1
        fi
        lua /usr/share/bypass2ray/run_scripts.lua bstart | while read l; do [ -z "$l" ] || echo $l && log $l; done
        ulimit -n 65535
        V2RAY_LOCATION_ASSET=$(config_n_get global resource_location "/usr/share/bypass2ray/")
        XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
        log "启动程序"
        nohup env v2ray.location.asset=$V2RAY_LOCATION_ASSET env xray.location.asset=$XRAY_LOCATION_ASSET $RUNFILE run -config $CONFIG >${TMPDIR}all.log 2>&1 &
        id=$(echo $!)
        log "PID: $id"
        echo $id >$PID
        lua /usr/share/bypass2ray/run_scripts.lua astart | while read l; do [ -z "$l" ] || echo $l && log $l; done
    fi
}

stop() {
    logcheck
    if [ ! -f "$PID" ]; then
        exit 1
    else
        log "==== 结束进程 ===="
        TMPDIR=$(config_n_get global tmp_dir "/tmp/bypass2ray/")
        if [ -z "$TMPDIR" ]; then
            echo "Temp Dir is nil"
            log "临时文件夹路径未找到"
            exit 1
        fi
        lua /usr/share/bypass2ray/run_scripts.lua bstop | while read l; do [ -z "$l" ] || echo $l && log $l; done
        kill $(cat $PID 2>/dev/null) >/dev/null 2>&1
        rm -f $PID
        log "结束进程: $(cat $PID)"
        if [ ! -z "$TMPDIR" ]; then
            rm -rf ${TMPDIR}*
        fi
        log "清空临时文件夹: $TMPDIR"
        lua /usr/share/bypass2ray/run_scripts.lua astop | while read l; do [ -z "$l" ] || echo $l && log $l; done
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
