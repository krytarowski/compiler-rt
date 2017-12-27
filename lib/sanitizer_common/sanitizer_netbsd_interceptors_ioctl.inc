//===-- sanitizer_common_interceptors_ioctl.inc -----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Ioctl handling in common sanitizer interceptors.
//===----------------------------------------------------------------------===//

#include "sanitizer_flags.h"

struct ioctl_desc {
  unsigned req;
  // FIXME: support read+write arguments. Currently READWRITE and WRITE do the
  // same thing.
  // XXX: The declarations below may use WRITE instead of READWRITE, unless
  // explicitly noted.
  enum { NONE, READ, WRITE, READWRITE, CUSTOM } type : 3;
  unsigned size : 29;
  const char *name;
};

const unsigned ioctl_table_max = 1333;
static ioctl_desc ioctl_table[ioctl_table_max];
static unsigned ioctl_table_size = 0;

// This can not be declared as a global, because references to struct_*_sz
// require a global initializer. And this table must be available before global
// initializers are run.
static void ioctl_table_fill() {
#define _(rq, tp, sz)                                                          \
  if (IOCTL_##rq != IOCTL_NOT_PRESENT) {                                       \
    CHECK(ioctl_table_size < ioctl_table_max);                                 \
    ioctl_table[ioctl_table_size].req = IOCTL_##rq;                            \
    ioctl_table[ioctl_table_size].type = ioctl_desc::tp;                       \
    ioctl_table[ioctl_table_size].size = sz;                                   \
    ioctl_table[ioctl_table_size].name = #rq;                                  \
    ++ioctl_table_size;                                                        \
  }

  /* Entries from file: altq/altq_afmap.h */
  _(AFM_ADDFMAP, READWRITE, struct atm_flowmap);
  _(AFM_DELFMAP, READWRITE, struct atm_flowmap);
  _(AFM_CLEANFMAP, READWRITE, struct atm_flowmap);
  _(AFM_GETFMAP, READWRITE, struct atm_flowmap);
  /* Entries from file: altq/altq.h */
  _(ALTQGTYPE, READWRITE, struct altqreq);
  _(ALTQATTACH, WRITE, struct altqreq);
  _(ALTQDETACH, WRITE, struct altqreq);
  _(ALTQENABLE, WRITE, struct altqreq);
  _(ALTQDISABLE, WRITE, struct altqreq);
  _(ALTQCLEAR, WRITE, struct altqreq);
  _(ALTQCONFIG, READWRITE, struct altqreq);
  _(ALTQADDCLASS, READWRITE, struct altqreq);
  _(ALTQMODCLASS, READWRITE, struct altqreq);
  _(ALTQDELCLASS, READWRITE, struct altqreq);
  _(ALTQADDFILTER, READWRITE, struct altqreq);
  _(ALTQDELFILTER, READWRITE, struct altqreq);
  _(ALTQGETSTATS, READWRITE, struct altqreq);
  _(ALTQGETCNTR, READWRITE, struct altqreq);
  _(ALTQTBRSET, WRITE, struct tbrreq);
  _(ALTQTBRGET, READWRITE, struct tbrreq);
  /* Entries from file: altq/altq_blue.h */
  _(BLUE_IF_ATTACH, WRITE, struct blue_interface);
  _(BLUE_IF_DETACH, WRITE, struct blue_interface);
  _(BLUE_ENABLE, WRITE, struct blue_interface);
  _(BLUE_DISABLE, WRITE, struct blue_interface);
  _(BLUE_CONFIG, READWRITE, struct blue_conf);
  _(BLUE_GETSTATS, READWRITE, struct blue_stats);
  /* Entries from file: altq/altq_cbq.h */
  _(CBQ_IF_ATTACH, WRITE, struct cbq_interface);
  _(CBQ_IF_DETACH, WRITE, struct cbq_interface);
  _(CBQ_ENABLE, WRITE, struct cbq_interface);
  _(CBQ_DISABLE, WRITE, struct cbq_interface);
  _(CBQ_CLEAR_HIERARCHY, WRITE, struct cbq_interface);
  _(CBQ_ADD_CLASS, READWRITE, struct cbq_add_class);
  _(CBQ_DEL_CLASS, WRITE, struct cbq_delete_class);
  _(CBQ_MODIFY_CLASS, READWRITE, struct cbq_modify_class);
  _(CBQ_ADD_FILTER, READWRITE, struct cbq_add_filter);
  _(CBQ_DEL_FILTER, WRITE, struct cbq_delete_filter);
  _(CBQ_GETSTATS, READWRITE, struct cbq_getstats);
  /* Entries from file: altq/altq_cdnr.h */
  _(CDNR_IF_ATTACH, WRITE, struct cdnr_interface);
  _(CDNR_IF_DETACH, WRITE, struct cdnr_interface);
  _(CDNR_ENABLE, WRITE, struct cdnr_interface);
  _(CDNR_DISABLE, WRITE, struct cdnr_interface);
  _(CDNR_ADD_FILTER, READWRITE, struct cdnr_add_filter);
  _(CDNR_DEL_FILTER, WRITE, struct cdnr_delete_filter);
  _(CDNR_GETSTATS, READWRITE, struct cdnr_get_stats);
  _(CDNR_ADD_ELEM, READWRITE, struct cdnr_add_element);
  _(CDNR_DEL_ELEM, WRITE, struct cdnr_delete_element);
  _(CDNR_ADD_TBM, READWRITE, struct cdnr_add_tbmeter);
  _(CDNR_MOD_TBM, WRITE, struct cdnr_modify_tbmeter);
  _(CDNR_TBM_STATS, READWRITE, struct cdnr_tbmeter_stats);
  _(CDNR_ADD_TCM, READWRITE, struct cdnr_add_trtcm);
  _(CDNR_MOD_TCM, READWRITE, struct cdnr_modify_trtcm);
  _(CDNR_TCM_STATS, READWRITE, struct cdnr_tcm_stats);
  _(CDNR_ADD_TSW, READWRITE, struct cdnr_add_tswtcm);
  _(CDNR_MOD_TSW, READWRITE, struct cdnr_modify_tswtcm);
  /* Entries from file: altq/altq_fifoq.h */
  _(FIFOQ_IF_ATTACH, WRITE, struct fifoq_interface);
  _(FIFOQ_IF_DETACH, WRITE, struct fifoq_interface);
  _(FIFOQ_ENABLE, WRITE, struct fifoq_interface);
  _(FIFOQ_DISABLE, WRITE, struct fifoq_interface);
  _(FIFOQ_CONFIG, READWRITE, struct fifoq_conf);
  _(FIFOQ_GETSTATS, READWRITE, struct fifoq_getstats);
  /* Entries from file: altq/altq_hfsc.h */
  _(HFSC_IF_ATTACH, WRITE, struct hfsc_attach);
  _(HFSC_IF_DETACH, WRITE, struct hfsc_interface);
  _(HFSC_ENABLE, WRITE, struct hfsc_interface);
  _(HFSC_DISABLE, WRITE, struct hfsc_interface);
  _(HFSC_CLEAR_HIERARCHY, WRITE, struct hfsc_interface);
  _(HFSC_ADD_CLASS, READWRITE, struct hfsc_add_class);
  _(HFSC_DEL_CLASS, WRITE, struct hfsc_delete_class);
  _(HFSC_MOD_CLASS, WRITE, struct hfsc_modify_class);
  _(HFSC_ADD_FILTER, READWRITE, struct hfsc_add_filter);
  _(HFSC_DEL_FILTER, WRITE, struct hfsc_delete_filter);
  _(HFSC_GETSTATS, READWRITE, struct hfsc_class_stats);
  /* Entries from file: altq/altq_jobs.h */
  _(JOBS_IF_ATTACH, WRITE, struct jobs_attach);
  _(JOBS_IF_DETACH, WRITE, struct jobs_interface);
  _(JOBS_ENABLE, WRITE, struct jobs_interface);
  _(JOBS_DISABLE, WRITE, struct jobs_interface);
  _(JOBS_CLEAR, WRITE, struct jobs_interface);
  _(JOBS_ADD_CLASS, READWRITE, struct jobs_add_class);
  _(JOBS_DEL_CLASS, WRITE, struct jobs_delete_class);
  _(JOBS_MOD_CLASS, WRITE, struct jobs_modify_class);
  _(JOBS_ADD_FILTER, READWRITE, struct jobs_add_filter);
  _(JOBS_DEL_FILTER, WRITE, struct jobs_delete_filter);
  _(JOBS_GETSTATS, READWRITE, struct jobs_class_stats);
  /* Entries from file: altq/altq_priq.h */
  _(PRIQ_IF_ATTACH, WRITE, struct priq_interface);
  _(PRIQ_IF_DETACH, WRITE, struct priq_interface);
  _(PRIQ_ENABLE, WRITE, struct priq_interface);
  _(PRIQ_DISABLE, WRITE, struct priq_interface);
  _(PRIQ_CLEAR, WRITE, struct priq_interface);
  _(PRIQ_ADD_CLASS, READWRITE, struct priq_add_class);
  _(PRIQ_DEL_CLASS, WRITE, struct priq_delete_class);
  _(PRIQ_MOD_CLASS, WRITE, struct priq_modify_class);
  _(PRIQ_ADD_FILTER, READWRITE, struct priq_add_filter);
  _(PRIQ_DEL_FILTER, WRITE, struct priq_delete_filter);
  _(PRIQ_GETSTATS, READWRITE, struct priq_class_stats);
  /* Entries from file: altq/altq_red.h */
  _(RED_IF_ATTACH, WRITE, struct red_interface);
  _(RED_IF_DETACH, WRITE, struct red_interface);
  _(RED_ENABLE, WRITE, struct red_interface);
  _(RED_DISABLE, WRITE, struct red_interface);
  _(RED_CONFIG, READWRITE, struct red_conf);
  _(RED_GETSTATS, READWRITE, struct red_stats);
  _(RED_SETDEFAULTS, WRITE, struct redparams);
  /* Entries from file: altq/altq_rio.h */
  _(RIO_IF_ATTACH, WRITE, struct rio_interface);
  _(RIO_IF_DETACH, WRITE, struct rio_interface);
  _(RIO_ENABLE, WRITE, struct rio_interface);
  _(RIO_DISABLE, WRITE, struct rio_interface);
  _(RIO_CONFIG, READWRITE, struct rio_conf);
  _(RIO_GETSTATS, READWRITE, struct rio_stats);
  _(RIO_SETDEFAULTS, WRITE, struct redparams);
  /* Entries from file: altq/altq_wfq.h */
  _(WFQ_IF_ATTACH, WRITE, struct wfq_interface);
  _(WFQ_IF_DETACH, WRITE, struct wfq_interface);
  _(WFQ_ENABLE, WRITE, struct wfq_interface);
  _(WFQ_DISABLE, WRITE, struct wfq_interface);
  _(WFQ_CONFIG, READWRITE, struct wfq_conf);
  _(WFQ_GET_STATS, READWRITE, struct wfq_getstats);
  _(WFQ_GET_QID, READWRITE, struct wfq_getqid);
  _(WFQ_SET_WEIGHT, READWRITE, struct wfq_setweight);
  /* Entries from file: crypto/cryptodev.h */
  _(CRIOGET, READWRITE, u_int32_t);
  _(CIOCFSESSION, WRITE, u_int32_t);
  _(CIOCKEY, READWRITE, struct crypt_kop);
  _(CIOCNFKEYM, READWRITE, struct crypt_mkop);
  _(CIOCNFSESSION, WRITE, struct crypt_sfop);
  _(CIOCNCRYPTRETM, READWRITE, struct cryptret);
  _(CIOCNCRYPTRET, READWRITE, struct crypt_result);
  _(CIOCGSESSION, READWRITE, struct session_op);
  _(CIOCNGSESSION, READWRITE, struct crypt_sgop);
  _(CIOCCRYPT, READWRITE, struct crypt_op);
  _(CIOCNCRYPTM, READWRITE, struct crypt_mop);
  _(CIOCASYMFEAT, READ, u_int32_t);
  /* Entries from file: dev/apm/apmio.h */
  _(APM_IOC_REJECT, WRITE, struct apm_event_info);
  _(APM_IOC_STANDBY, NONE);
  _(APM_IOC_SUSPEND, NONE);
  _(OAPM_IOC_GETPOWER, READ, struct apm_power_info);
  _(APM_IOC_GETPOWER, READWRITE, struct apm_power_info);
  _(APM_IOC_NEXTEVENT, READ, struct apm_event_info);
  _(APM_IOC_DEV_CTL, WRITE, struct apm_ctl);
  /* Entries from file: dev/dm/netbsd-dm.h */
  _(NETBSD_DM_IOCTL, READWRITE, struct plistref);
  /* Entries from file: dev/dmover/dmover_io.h */
  _(DMIO_SETFUNC, WRITE, struct dmio_setfunc);
  /* Entries from file: dev/dtv/dtvio_demux.h */
  _(DMX_START, NONE);
  _(DMX_STOP, NONE);
  _(DMX_SET_FILTER, WRITE, struct dmx_sct_filter_params);
  _(DMX_SET_PES_FILTER, WRITE, struct dmx_pes_filter_params);
  _(DMX_SET_BUFFER_SIZE, NONE);
  _(DMX_GET_STC, READWRITE, struct dmx_stc);
  _(DMX_ADD_PID, WRITE, uint16_t);
  _(DMX_REMOVE_PID, WRITE, uint16_t);
  _(DMX_GET_CAPS, READ, dmx_caps_t);
  _(DMX_SET_SOURCE, WRITE, dmx_source_t);
  /* Entries from file: dev/dtv/dtvio_frontend.h */
  _(FE_READ_STATUS, READ, fe_status_t);
  _(FE_READ_BER, READ, uint32_t);
  _(FE_READ_SNR, READ, uint16_t);
  _(FE_READ_SIGNAL_STRENGTH, READ, uint16_t);
  _(FE_READ_UNCORRECTED_BLOCKS, READ, uint32_t);
  _(FE_SET_FRONTEND, READWRITE, struct dvb_frontend_parameters);
  _(FE_GET_FRONTEND, READ, struct dvb_frontend_parameters);
  _(FE_GET_EVENT, READ, struct dvb_frontend_event);
  _(FE_GET_INFO, READ, struct dvb_frontend_info);
  _(FE_DISEQC_RESET_OVERLOAD, NONE);
  _(FE_DISEQC_SEND_MASTER_CMD, WRITE, struct dvb_diseqc_master_cmd);
  _(FE_DISEQC_RECV_SLAVE_REPLY, READ, struct dvb_diseqc_slave_reply);
  _(FE_DISEQC_SEND_BURST, WRITE, fe_sec_mini_cmd_t);
  _(FE_SET_TONE, WRITE, fe_sec_tone_mode_t);
  _(FE_SET_VOLTAGE, WRITE, fe_sec_voltage_t);
  _(FE_ENABLE_HIGH_LNB_VOLTAGE, WRITE, sizeof(int));
  _(FE_SET_FRONTEND_TUNE_MODE, WRITE, unsigned int);
  _(FE_DISHNETWORK_SEND_LEGACY_CMD, WRITE, unsigned long);
  /* Entries from file: dev/filemon/filemon.h */
  _(FILEMON_SET_FD, READWRITE, sizeof(int));
  _(FILEMON_SET_PID, READWRITE, pid_t);
  /* Entries from file: dev/hdaudio/hdaudioio.h */
  _(HDAUDIO_FGRP_INFO, READWRITE, struct plistref);
  _(HDAUDIO_FGRP_GETCONFIG, READWRITE, struct plistref);
  _(HDAUDIO_FGRP_SETCONFIG, READWRITE, struct plistref);
  _(HDAUDIO_FGRP_WIDGET_INFO, READWRITE, struct plistref);
  _(HDAUDIO_FGRP_CODEC_INFO, READWRITE, struct plistref);
  _(HDAUDIO_AFG_WIDGET_INFO, READWRITE, struct plistref);
  _(HDAUDIO_AFG_CODEC_INFO, READWRITE, struct plistref);
  /* Entries from file: dev/hdmicec/hdmicecio.h */
  _(CEC_GET_PHYS_ADDR, READ, uint16_t);
  _(CEC_GET_LOG_ADDRS, READ, uint16_t);
  _(CEC_SET_LOG_ADDRS, WRITE, uint16_t);
  _(CEC_GET_VENDOR_ID, READ, uint32_t);
  /* Entries from file: dev/hpc/hpcfbio.h */
  _(HPCFBIO_GCONF, READWRITE, struct hpcfb_fbconf);
  _(HPCFBIO_SCONF, WRITE, struct hpcfb_fbconf);
  _(HPCFBIO_GDSPCONF, READWRITE, struct hpcfb_dspconf);
  _(HPCFBIO_SDSPCONF, WRITE, struct hpcfb_dspconf);
  _(HPCFBIO_GOP, READ, struct hpcfb_dsp_op);
  _(HPCFBIO_SOP, READWRITE, struct hpcfb_dsp_op);
  /* Entries from file: dev/i2o/iopio.h */
  _(IOPIOCPT, READWRITE, struct ioppt);
  _(IOPIOCGLCT, READWRITE, struct iovec);
  _(IOPIOCGSTATUS, READWRITE, struct iovec);
  _(IOPIOCRECONFIG, NONE);
  _(IOPIOCGTIDMAP, READWRITE, struct iovec);
  /* Entries from file: dev/ic/athioctl.h */
  _(SIOCGATHSTATS, READWRITE, struct ifreq);
  _(SIOCGATHDIAG, READWRITE, struct ath_diag);
  /* Entries from file: dev/ic/bt8xx.h */
  _(METEORCAPTUR, WRITE, sizeof(int));
  _(METEORCAPFRM, WRITE, struct meteor_capframe);
  _(METEORSETGEO, WRITE, struct meteor_geomet);
  _(METEORGETGEO, READ, struct meteor_geomet);
  _(METEORSTATUS, READ, unsigned short);
  _(METEORSHUE, WRITE, signed char);
  _(METEORGHUE, READ, signed char);
  _(METEORSFMT, WRITE, unsigned int);
  _(METEORGFMT, READ, unsigned int);
  _(METEORSINPUT, WRITE, unsigned int);
  _(METEORGINPUT, READ, unsigned int);
  _(METEORSCHCV, WRITE, unsigned char);
  _(METEORGCHCV, READ, unsigned char);
  _(METEORSCOUNT, WRITE, struct meteor_counts);
  _(METEORGCOUNT, READ, struct meteor_counts);
  _(METEORSFPS, WRITE, unsigned short);
  _(METEORGFPS, READ, unsigned short);
  _(METEORSSIGNAL, WRITE, unsigned int);
  _(METEORGSIGNAL, READ, unsigned int);
  _(METEORSVIDEO, WRITE, struct meteor_video);
  _(METEORGVIDEO, READ, struct meteor_video);
  _(METEORSBRIG, WRITE, unsigned char);
  _(METEORGBRIG, READ, unsigned char);
  _(METEORSCSAT, WRITE, unsigned char);
  _(METEORGCSAT, READ, unsigned char);
  _(METEORSCONT, WRITE, unsigned char);
  _(METEORGCONT, READ, unsigned char);
  _(METEORSHWS, WRITE, unsigned char);
  _(METEORGHWS, READ, unsigned char);
  _(METEORSVWS, WRITE, unsigned char);
  _(METEORGVWS, READ, unsigned char);
  _(METEORSTS, WRITE, unsigned char);
  _(METEORGTS, READ, unsigned char);
  _(TVTUNER_SETCHNL, WRITE, unsigned int);
  _(TVTUNER_GETCHNL, READ, unsigned int);
  _(TVTUNER_SETTYPE, WRITE, unsigned int);
  _(TVTUNER_GETTYPE, READ, unsigned int);
  _(TVTUNER_GETSTATUS, READ, unsigned int);
  _(TVTUNER_SETFREQ, WRITE, unsigned int);
  _(TVTUNER_GETFREQ, READ, unsigned int);
  _(TVTUNER_SETAFC, WRITE, sizeof(int));
  _(TVTUNER_GETAFC, READ, sizeof(int));
  _(RADIO_SETMODE, WRITE, unsigned int);
  _(RADIO_GETMODE, READ, unsigned char);
  _(RADIO_SETFREQ, WRITE, unsigned int);
  _(RADIO_GETFREQ, READ, unsigned int);
  _(METEORSACTPIXFMT, WRITE, sizeof(int));
  _(METEORGACTPIXFMT, READ, sizeof(int));
  _(METEORGSUPPIXFMT, READWRITE, struct meteor_pixfmt);
  _(TVTUNER_GETCHNLSET, READWRITE, struct bktr_chnlset);
  _(REMOTE_GETKEY, READ, struct bktr_remote);
  /* Entries from file: dev/ic/hd44780var.h */
  _(HLCD_DISPCTL, WRITE, struct hd44780_dispctl);
  _(HLCD_RESET, NONE);
  _(HLCD_CLEAR, NONE);
  _(HLCD_CURSOR_LEFT, NONE);
  _(HLCD_CURSOR_RIGHT, NONE);
  _(HLCD_GET_CURSOR_POS, READ, struct hd44780_io);
  _(HLCD_SET_CURSOR_POS, WRITE, struct hd44780_io);
  _(HLCD_GETC, READ, struct hd44780_io);
  _(HLCD_PUTC, WRITE, struct hd44780_io);
  _(HLCD_SHIFT_LEFT, NONE);
  _(HLCD_SHIFT_RIGHT, NONE);
  _(HLCD_HOME, NONE);
  _(HLCD_WRITE, READWRITE, struct hd44780_io);
  _(HLCD_READ, READWRITE, struct hd44780_io);
  _(HLCD_REDRAW, WRITE, struct hd44780_io);
  _(HLCD_WRITE_INST, WRITE, struct hd44780_io);
  _(HLCD_WRITE_DATA, WRITE, struct hd44780_io);
  _(HLCD_GET_INFO, READ, struct hd44780_info);
  _(HLCD_GET_CHIPNO, READ, uint8_t);
  _(HLCD_SET_CHIPNO, WRITE, uint8_t);
  /* Entries from file: dev/ic/icp_ioctl.h */
  _(GDT_IOCTL_GENERAL, READWRITE, gdt_ucmd_t);
  _(GDT_IOCTL_DRVERS, READ, sizeof(int));
  _(GDT_IOCTL_CTRTYPE, READWRITE, gdt_ctrt_t);
  _(GDT_IOCTL_OSVERS, READ, gdt_osv_t);
  _(GDT_IOCTL_CTRCNT, READ, sizeof(int));
  _(GDT_IOCTL_EVENT, READWRITE, gdt_event_t);
  _(GDT_IOCTL_STATIST, READ, gdt_statist_t);
  _(GDT_IOCTL_RESCAN, READWRITE, gdt_rescan_t);
  /* Entries from file: dev/ic/isp_ioctl.h */
  _(ISP_SDBLEV, READWRITE, sizeof(int));
  _(ISP_RESETHBA, NONE);
  _(ISP_RESCAN, NONE);
  _(ISP_SETROLE, READWRITE, sizeof(int));
  _(ISP_GETROLE, READ, sizeof(int));
  _(ISP_GET_STATS, READ, isp_stats_t);
  _(ISP_CLR_STATS, NONE);
  _(ISP_FC_LIP, NONE);
  _(ISP_FC_GETDINFO, READWRITE, struct isp_fc_device);
  _(ISP_GET_FW_CRASH_DUMP, NONE);
  _(ISP_FORCE_CRASH_DUMP, NONE);
  _(ISP_FC_GETHINFO, READWRITE, struct isp_hba_device);
  _(ISP_TSK_MGMT, READWRITE, struct isp_fc_tsk_mgmt);
  _(ISP_FC_GETDLIST, NONE);
  /* Entries from file: dev/ic/mlxio.h */
  _(MLXD_STATUS, READ, sizeof(int));
  _(MLXD_CHECKASYNC, READ, sizeof(int));
  _(MLXD_DETACH, WRITE, sizeof(int));
  _(MLX_RESCAN_DRIVES, NONE);
  _(MLX_PAUSE_CHANNEL, WRITE, struct mlx_pause);
  _(MLX_COMMAND, READWRITE, struct mlx_usercommand);
  _(MLX_REBUILDASYNC, READWRITE, struct mlx_rebuild_request);
  _(MLX_REBUILDSTAT, READ, struct mlx_rebuild_status);
  _(MLX_GET_SYSDRIVE, READWRITE, sizeof(int));
  _(MLX_GET_CINFO, READ, struct mlx_cinfo);
  /* Entries from file: dev/ic/nvmeio.h */
  _(NVME_PASSTHROUGH_CMD, READWRITE, struct nvme_pt_command);
  /* Entries from file: dev/ir/irdaio.h */
  _(IRDA_RESET_PARAMS, NONE);
  _(IRDA_SET_PARAMS, WRITE, struct irda_params);
  _(IRDA_GET_SPEEDMASK, READ, unsigned int);
  _(IRDA_GET_TURNAROUNDMASK, READ, unsigned int);
  _(IRFRAMETTY_GET_DEVICE, READ, unsigned int);
  _(IRFRAMETTY_GET_DONGLE, READ, unsigned int);
  _(IRFRAMETTY_SET_DONGLE, WRITE, unsigned int);
  /* Entries from file: dev/isa/satlinkio.h */
  _(SATIORESET, NONE);
  _(SATIOGID, READ, struct satlink_id);
  _(SATIOSBUFSIZE, WRITE, sizeof(int));
  /* Entries from file: dev/isa/isvio.h */
  _(ISV_CMD, READWRITE, struct isv_cmd);
  /* Entries from file: dev/isa/wtreg.h */
  _(WTQICMD, NONE);
  /* Entries from file: dev/iscsi/iscsi_ioctl.h */
  _(ISCSI_GET_VERSION, READWRITE, iscsi_get_version_parameters_t);
  _(ISCSI_LOGIN, READWRITE, iscsi_login_parameters_t);
  _(ISCSI_LOGOUT, READWRITE, iscsi_logout_parameters_t);
  _(ISCSI_ADD_CONNECTION, READWRITE, iscsi_login_parameters_t);
  _(ISCSI_RESTORE_CONNECTION, READWRITE, iscsi_login_parameters_t);
  _(ISCSI_REMOVE_CONNECTION, READWRITE, iscsi_remove_parameters_t);
  _(ISCSI_CONNECTION_STATUS, READWRITE, iscsi_conn_status_parameters_t);
  _(ISCSI_SEND_TARGETS, READWRITE, iscsi_send_targets_parameters_t);
  _(ISCSI_SET_NODE_NAME, READWRITE, iscsi_set_node_name_parameters_t);
  _(ISCSI_IO_COMMAND, READWRITE, iscsi_iocommand_parameters_t);
  _(ISCSI_REGISTER_EVENT, READWRITE, iscsi_register_event_parameters_t);
  _(ISCSI_DEREGISTER_EVENT, READWRITE, iscsi_register_event_parameters_t);
  _(ISCSI_WAIT_EVENT, READWRITE, iscsi_wait_event_parameters_t);
  _(ISCSI_POLL_EVENT, READWRITE, iscsi_wait_event_parameters_t);
  /* Entries from file: dev/ofw/openfirmio.h */
  _(OFIOCGET, READWRITE, struct ofiocdesc);
  _(OFIOCSET, WRITE, struct ofiocdesc);
  _(OFIOCNEXTPROP, READWRITE, struct ofiocdesc);
  _(OFIOCGETOPTNODE, READ, sizeof(int));
  _(OFIOCGETNEXT, READWRITE, sizeof(int));
  _(OFIOCGETCHILD, READWRITE, sizeof(int));
  _(OFIOCFINDDEVICE, READWRITE, struct ofiocdesc);
  /* Entries from file: dev/pci/amrio.h */
  _(AMR_IO_VERSION, READ, sizeof(int));
  _(AMR_IO_COMMAND, READWRITE, struct amr_user_ioctl);
  /* Entries from file: dev/pci/mlyio.h */
  _(MLYIO_COMMAND, READWRITE, struct mly_user_command);
  _(MLYIO_HEALTH, WRITE, struct mly_user_health);
  /* Entries from file: dev/pci/pciio.h */
  _(PCI_IOC_CFGREAD, READWRITE, struct pciio_cfgreg);
  _(PCI_IOC_CFGWRITE, WRITE, struct pciio_cfgreg);
  _(PCI_IOC_BDF_CFGREAD, READWRITE, struct pciio_bdf_cfgreg);
  _(PCI_IOC_BDF_CFGWRITE, WRITE, struct pciio_bdf_cfgreg);
  _(PCI_IOC_BUSINFO, READ, struct pciio_businfo);
  _(PCI_IOC_DRVNAME, READWRITE, struct pciio_drvname);
  _(PCI_IOC_DRVNAMEONBUS, READWRITE, struct pciio_drvnameonbus);
  /* Entries from file: dev/pci/tweio.h */
  _(TWEIO_COMMAND, READWRITE, struct twe_usercommand);
  _(TWEIO_STATS, READWRITE, union twe_statrequest);
  _(TWEIO_AEN_POLL, READ, sizeof(int));
  _(TWEIO_AEN_WAIT, READ, sizeof(int));
  _(TWEIO_SET_PARAM, WRITE, struct twe_paramcommand);
  _(TWEIO_GET_PARAM, WRITE, struct twe_paramcommand);
  _(TWEIO_RESET, NONE);
  _(TWEIO_ADD_UNIT, WRITE, struct twe_drivecommand);
  _(TWEIO_DEL_UNIT, WRITE, struct twe_drivecommand);
  /* Entries from file: dev/pcmcia/if_cnwioctl.h */
  _(SIOCSCNWDOMAIN, WRITE, struct ifreq);
  _(SIOCGCNWDOMAIN, READWRITE, struct ifreq);
  _(SIOCSCNWKEY, READWRITE, struct ifreq);
  _(SIOCGCNWSTATUS, READWRITE, struct cnwstatus);
  _(SIOCGCNWSTATS, READWRITE, struct cnwistats);
  _(SIOCGCNWTRAIL, READWRITE, struct cnwitrail);
  /* Entries from file: dev/pcmcia/if_rayreg.h */
  _(SIOCGRAYSIGLEV, READWRITE, struct ifreq);
  /* Entries from file: dev/raidframe/raidframeio.h */
  _(RAIDFRAME_SHUTDOWN, NONE);
  _(RAIDFRAME_TUR, WRITE, dev_t);
  _(RAIDFRAME_TEST_ACC, READWRITE, struct rf_test_acc);
  _(RAIDFRAME_FAIL_DISK, WRITE, struct rf_recon_req);
  _(RAIDFRAME_CHECK_RECON_STATUS, READWRITE, sizeof(int));
  _(RAIDFRAME_REWRITEPARITY, NONE);
  _(RAIDFRAME_COPYBACK, NONE);
  _(RAIDFRAME_SPARET_WAIT, READ, RF_SparetWait_t);
  _(RAIDFRAME_SEND_SPARET, WRITE, void);
  _(RAIDFRAME_ABORT_SPARET_WAIT, NONE);
  _(RAIDFRAME_START_ATRACE, NONE);
  _(RAIDFRAME_STOP_ATRACE, NONE);
  _(RAIDFRAME_GET_SIZE, READ, sizeof(int));
  _(RAIDFRAME_RESET_ACCTOTALS, NONE);
  _(RAIDFRAME_GET_ACCTOTALS, READ, RF_AccTotals_t);
  _(RAIDFRAME_KEEP_ACCTOTALS, WRITE, sizeof(int));
  _(RAIDFRAME_GET_COMPONENT_LABEL, READWRITE, RF_ComponentLabel_t);
  _(RAIDFRAME_SET_COMPONENT_LABEL, WRITE, RF_ComponentLabel_t);
  _(RAIDFRAME_INIT_LABELS, WRITE, RF_ComponentLabel_t);
  _(RAIDFRAME_ADD_HOT_SPARE, WRITE, RF_SingleComponent_t);
  _(RAIDFRAME_REMOVE_HOT_SPARE, WRITE, RF_SingleComponent_t);
  _(RAIDFRAME_REBUILD_IN_PLACE, WRITE, RF_SingleComponent_t);
  _(RAIDFRAME_CHECK_PARITY, READWRITE, sizeof(int));
  _(RAIDFRAME_CHECK_PARITYREWRITE_STATUS, READWRITE, sizeof(int));
  _(RAIDFRAME_CHECK_COPYBACK_STATUS, READWRITE, sizeof(int));
  _(RAIDFRAME_SET_AUTOCONFIG, READWRITE, sizeof(int));
  _(RAIDFRAME_SET_ROOT, READWRITE, sizeof(int));
  _(RAIDFRAME_DELETE_COMPONENT, WRITE, RF_SingleComponent_t);
  _(RAIDFRAME_INCORPORATE_HOT_SPARE, WRITE, RF_SingleComponent_t);
  _(RAIDFRAME_CHECK_RECON_STATUS_EXT, READWRITE, RF_ProgressInfo_t);
  _(RAIDFRAME_CHECK_PARITYREWRITE_STATUS_EXT, READWRITE, RF_ProgressInfo_t);
  _(RAIDFRAME_CHECK_COPYBACK_STATUS_EXT, READWRITE, RF_ProgressInfo_t);
  _(RAIDFRAME_CONFIGURE, WRITE, void);
  _(RAIDFRAME_GET_INFO, READWRITE, RF_DeviceConfig_t);
  _(RAIDFRAME_PARITYMAP_STATUS, READ, struct rf_pmstat);
  _(RAIDFRAME_PARITYMAP_GET_DISABLE, READ, sizeof(int));
  _(RAIDFRAME_PARITYMAP_SET_DISABLE, WRITE, sizeof(int));
  _(RAIDFRAME_PARITYMAP_SET_PARAMS, WRITE, struct rf_pmparams);
  _(RAIDFRAME_SET_LAST_UNIT, WRITE, sizeof(int));
  /* Entries from file: dev/sbus/mbppio.h */
  _(MBPPIOCSPARAM, WRITE, struct mbpp_param);
  _(MBPPIOCGPARAM, READ, struct mbpp_param);
  _(MBPPIOCGSTAT, READ, sizeof(int));
  /* Entries from file: dev/scsipi/ses.h */
  _(SESIOC_GETNOBJ, NONE);
  _(SESIOC_GETOBJMAP, NONE);
  _(SESIOC_GETENCSTAT, NONE);
  _(SESIOC_SETENCSTAT, NONE);
  _(SESIOC_GETOBJSTAT, NONE);
  _(SESIOC_SETOBJSTAT, NONE);
  _(SESIOC_GETTEXT, NONE);
  _(SESIOC_INIT, NONE);
  /* Entries from file: dev/sun/disklabel.h */
  _(SUN_DKIOCGGEOM, READ, struct sun_dkgeom);
  _(SUN_DKIOCINFO, READ, struct sun_dkctlr);
  _(SUN_DKIOCGPART, READ, struct sun_dkpart);
  /* Entries from file: dev/sun/fbio.h */
  _(FBIOGTYPE, READ, struct fbtype);
  _(FBIOGINFO, READ, struct fbinfo);
  _(FBIOPUTCMAP, WRITE, struct fbcmap);
  _(FBIOGETCMAP, WRITE, struct fbcmap);
  _(FBIOSATTR, WRITE, struct fbsattr);
  _(FBIOGATTR, READ, struct fbgattr);
  _(FBIOSVIDEO, WRITE, sizeof(int));
  _(FBIOGVIDEO, READ, sizeof(int));
  _(FBIOSCURSOR, WRITE, struct fbcursor);
  _(FBIOGCURSOR, READWRITE, struct fbcursor);
  _(FBIOSCURPOS, WRITE, struct fbcurpos);
  _(FBIOGCURPOS, WRITE, struct fbcurpos);
  _(FBIOGCURMAX, READ, struct fbcurpos);
  /* Entries from file: dev/sun/kbio.h */
  _(KIOCTRANS, WRITE, sizeof(int));
  _(KIOCSETKEY, READWRITE, struct okiockey);
  _(KIOCGETKEY, READWRITE, struct okiockey);
  _(KIOCGTRANS, READ, sizeof(int));
  _(KIOCCMD, WRITE, sizeof(int));
  _(KIOCTYPE, READ, sizeof(int));
  _(KIOCSDIRECT, WRITE, sizeof(int));
  _(KIOCSKEY, WRITE, struct kiockeymap);
  _(KIOCGKEY, READWRITE, struct kiockeymap);
  _(KIOCSLED, WRITE, char);
  _(KIOCGLED, READ, char);
  _(KIOCLAYOUT, READ, sizeof(int));
  /* Entries from file: dev/sun/vuid_event.h */
  _(VUIDSFORMAT, WRITE, sizeof(int));
  _(VUIDGFORMAT, READ, sizeof(int));
  /* Entries from file: dev/tc/sticio.h */
  _(STICIO_GXINFO, READ, struct stic_xinfo);
  _(STICIO_RESET, NONE);
  _(STICIO_STARTQ, NONE);
  _(STICIO_STOPQ, NONE);
  /* Entries from file: dev/usb/ukyopon.h */
  _(UKYOPON_IDENTIFY, READ, struct ukyopon_identify);
  /* Entries from file: dev/usb/urio.h */
  _(URIO_SEND_COMMAND, READWRITE, struct urio_command);
  _(URIO_RECV_COMMAND, READWRITE, struct urio_command);
  /* Entries from file: dev/usb/usb.h */
  _(USB_REQUEST, READWRITE, struct usb_ctl_request);
  _(USB_SETDEBUG, WRITE, sizeof(int));
  _(USB_DISCOVER, NONE);
  _(USB_DEVICEINFO, READWRITE, struct usb_device_info);
  _(USB_DEVICEINFO_OLD, READWRITE, struct usb_device_info_old);
  _(USB_DEVICESTATS, READ, struct usb_device_stats);
  _(USB_GET_REPORT_DESC, READ, struct usb_ctl_report_desc);
  _(USB_SET_IMMED, WRITE, sizeof(int));
  _(USB_GET_REPORT, READWRITE, struct usb_ctl_report);
  _(USB_SET_REPORT, WRITE, struct usb_ctl_report);
  _(USB_GET_REPORT_ID, READ, sizeof(int));
  _(USB_GET_CONFIG, READ, sizeof(int));
  _(USB_SET_CONFIG, WRITE, sizeof(int));
  _(USB_GET_ALTINTERFACE, READWRITE, struct usb_alt_interface);
  _(USB_SET_ALTINTERFACE, READWRITE, struct usb_alt_interface);
  _(USB_GET_NO_ALT, READWRITE, struct usb_alt_interface);
  _(USB_GET_DEVICE_DESC, READ, usb_device_descriptor_t);
  _(USB_GET_CONFIG_DESC, READWRITE, struct usb_config_desc);
  _(USB_GET_INTERFACE_DESC, READWRITE, struct usb_interface_desc);
  _(USB_GET_ENDPOINT_DESC, READWRITE, struct usb_endpoint_desc);
  _(USB_GET_FULL_DESC, READWRITE, struct usb_full_desc);
  _(USB_GET_STRING_DESC, READWRITE, struct usb_string_desc);
  _(USB_DO_REQUEST, READWRITE, struct usb_ctl_request);
  _(USB_GET_DEVICEINFO, READ, struct usb_device_info);
  _(USB_GET_DEVICEINFO_OLD, READ, struct usb_device_info_old);
  _(USB_SET_SHORT_XFER, WRITE, sizeof(int));
  _(USB_SET_TIMEOUT, WRITE, sizeof(int));
  _(USB_SET_BULK_RA, WRITE, sizeof(int));
  _(USB_SET_BULK_WB, WRITE, sizeof(int));
  _(USB_SET_BULK_RA_OPT, WRITE, struct usb_bulk_ra_wb_opt);
  _(USB_SET_BULK_WB_OPT, WRITE, struct usb_bulk_ra_wb_opt);
  _(USB_GET_CM_OVER_DATA, READ, sizeof(int));
  _(USB_SET_CM_OVER_DATA, WRITE, sizeof(int));
  /* Entries from file: dev/usb/utoppy.h */
  _(UTOPPYIOTURBO, WRITE, sizeof(int));
  _(UTOPPYIOCANCEL, NONE);
  _(UTOPPYIOREBOOT, NONE);
  _(UTOPPYIOSTATS, READ, struct utoppy_stats);
  _(UTOPPYIORENAME, WRITE, struct utoppy_rename);
  _(UTOPPYIOMKDIR, WRITE, char);
  _(UTOPPYIODELETE, WRITE, char);
  _(UTOPPYIOREADDIR, WRITE, char);
  _(UTOPPYIOREADFILE, WRITE, struct utoppy_readfile);
  _(UTOPPYIOWRITEFILE, WRITE, struct utoppy_writefile);
  /* Entries from file: dev/vme/xio.h */
  _(DIOSXDCMD, READWRITE, struct xd_iocmd);
  /* Entries from file: dev/wscons/wsdisplay_usl_io.h */
  _(VT_OPENQRY, READ, sizeof(int));
  _(VT_SETMODE, WRITE, vtmode_t);
  _(VT_GETMODE, READ, vtmode_t);
  _(VT_RELDISP, NONE);
  _(VT_ACTIVATE, NONE);
  _(VT_WAITACTIVE, NONE);
  _(VT_GETACTIVE, READ, sizeof(int));
  _(VT_GETSTATE, READ, struct vt_stat);
  _(KDGETKBENT, READWRITE, struct kbentry);
  _(KDGKBMODE, READ, sizeof(int));
  _(KDSKBMODE, NONE);
  _(KDMKTONE, NONE);
  _(KDSETMODE, NONE);
  _(KDENABIO, NONE);
  _(KDDISABIO, NONE);
  _(KDGKBTYPE, READ, char);
  _(KDGETLED, READ, sizeof(int));
  _(KDSETLED, NONE);
  _(KDSETRAD, NONE);
  _(VGAPCVTID, READWRITE, struct pcvtid);
  _(CONS_GETVERS, READ, sizeof(int));
  /* Entries from file: dev/wscons/wsconsio.h */
  _(WSKBDIO_GTYPE, READ, u_int);
  _(WSKBDIO_BELL, NONE);
  _(WSKBDIO_COMPLEXBELL, WRITE, struct wskbd_bell_data);
  _(WSKBDIO_SETBELL, WRITE, struct wskbd_bell_data);
  _(WSKBDIO_GETBELL, READ, struct wskbd_bell_data);
  _(WSKBDIO_SETDEFAULTBELL, WRITE, struct wskbd_bell_data);
  _(WSKBDIO_GETDEFAULTBELL, READ, struct wskbd_bell_data);
  _(WSKBDIO_SETKEYREPEAT, WRITE, struct wskbd_keyrepeat_data);
  _(WSKBDIO_GETKEYREPEAT, READ, struct wskbd_keyrepeat_data);
  _(WSKBDIO_SETDEFAULTKEYREPEAT, WRITE, struct wskbd_keyrepeat_data);
  _(WSKBDIO_GETDEFAULTKEYREPEAT, READ, struct wskbd_keyrepeat_data);
  _(WSKBDIO_SETLEDS, WRITE, sizeof(int));
  _(WSKBDIO_GETLEDS, READ, sizeof(int));
  _(WSKBDIO_GETMAP, READWRITE, struct wskbd_map_data);
  _(WSKBDIO_SETMAP, WRITE, struct wskbd_map_data);
  _(WSKBDIO_GETENCODING, READ, kbd_t);
  _(WSKBDIO_SETENCODING, WRITE, kbd_t);
  _(WSKBDIO_SETMODE, WRITE, sizeof(int));
  _(WSKBDIO_GETMODE, READ, sizeof(int));
  _(WSKBDIO_SETKEYCLICK, WRITE, sizeof(int));
  _(WSKBDIO_GETKEYCLICK, READ, sizeof(int));
  _(WSKBDIO_GETSCROLL, READ, struct wskbd_scroll_data);
  _(WSKBDIO_SETSCROLL, WRITE, struct wskbd_scroll_data);
  _(WSKBDIO_SETVERSION, WRITE, sizeof(int));
  _(WSMOUSEIO_GTYPE, READ, u_int);
  _(WSMOUSEIO_SRES, WRITE, u_int);
  _(WSMOUSEIO_SSCALE, WRITE, u_int);
  _(WSMOUSEIO_SRATE, WRITE, u_int);
  _(WSMOUSEIO_SCALIBCOORDS, WRITE, struct wsmouse_calibcoords);
  _(WSMOUSEIO_GCALIBCOORDS, READ, struct wsmouse_calibcoords);
  _(WSMOUSEIO_GETID, READWRITE, struct wsmouse_id);
  _(WSMOUSEIO_GETREPEAT, READ, struct wsmouse_repeat);
  _(WSMOUSEIO_SETREPEAT, WRITE, struct wsmouse_repeat);
  _(WSMOUSEIO_SETVERSION, WRITE, sizeof(int));
  _(WSDISPLAYIO_GTYPE, READ, u_int);
  _(WSDISPLAYIO_GINFO, READ, struct wsdisplay_fbinfo);
  _(WSDISPLAYIO_GETCMAP, WRITE, struct wsdisplay_cmap);
  _(WSDISPLAYIO_PUTCMAP, WRITE, struct wsdisplay_cmap);
  _(WSDISPLAYIO_GVIDEO, READ, u_int);
  _(WSDISPLAYIO_SVIDEO, WRITE, u_int);
  _(WSDISPLAYIO_GCURPOS, READ, struct wsdisplay_curpos);
  _(WSDISPLAYIO_SCURPOS, WRITE, struct wsdisplay_curpos);
  _(WSDISPLAYIO_GCURMAX, READ, struct wsdisplay_curpos);
  _(WSDISPLAYIO_GCURSOR, READWRITE, struct wsdisplay_cursor);
  _(WSDISPLAYIO_SCURSOR, WRITE, struct wsdisplay_cursor);
  _(WSDISPLAYIO_GMODE, READ, u_int);
  _(WSDISPLAYIO_SMODE, WRITE, u_int);
  _(WSDISPLAYIO_LDFONT, WRITE, struct wsdisplay_font);
  _(WSDISPLAYIO_ADDSCREEN, WRITE, struct wsdisplay_addscreendata);
  _(WSDISPLAYIO_DELSCREEN, WRITE, struct wsdisplay_delscreendata);
  _(WSDISPLAYIO_SFONT, WRITE, struct wsdisplay_usefontdata);
  _(_O_WSDISPLAYIO_SETKEYBOARD, READWRITE, struct wsdisplay_kbddata);
  _(WSDISPLAYIO_GETPARAM, READWRITE, struct wsdisplay_param);
  _(WSDISPLAYIO_SETPARAM, READWRITE, struct wsdisplay_param);
  _(WSDISPLAYIO_GETACTIVESCREEN, READ, sizeof(int));
  _(WSDISPLAYIO_GETWSCHAR, READWRITE, struct wsdisplay_char);
  _(WSDISPLAYIO_PUTWSCHAR, READWRITE, struct wsdisplay_char);
  _(WSDISPLAYIO_DGSCROLL, READ, struct wsdisplay_scroll_data);
  _(WSDISPLAYIO_DSSCROLL, WRITE, struct wsdisplay_scroll_data);
  _(WSDISPLAYIO_GMSGATTRS, READ, struct wsdisplay_msgattrs);
  _(WSDISPLAYIO_SMSGATTRS, WRITE, struct wsdisplay_msgattrs);
  _(WSDISPLAYIO_GBORDER, READ, sizeof(int));
  _(WSDISPLAYIO_SBORDER, WRITE, sizeof(int));
  _(WSDISPLAYIO_SSPLASH, WRITE, sizeof(int));
  _(WSDISPLAYIO_SPROGRESS, WRITE, sizeof(int));
  _(WSDISPLAYIO_LINEBYTES, READ, u_int);
  _(WSDISPLAYIO_SETVERSION, WRITE, sizeof(int));
  _(WSMUXIO_ADD_DEVICE, WRITE, struct wsmux_device);
  _(WSMUXIO_REMOVE_DEVICE, WRITE, struct wsmux_device);
  _(WSMUXIO_LIST_DEVICES, READWRITE, struct wsmux_device_list);
  _(WSMUXIO_INJECTEVENT, WRITE, struct wscons_event);
  _(WSDISPLAYIO_GET_BUSID, READ, struct wsdisplayio_bus_id);
  _(WSDISPLAYIO_GET_EDID, READWRITE, struct wsdisplayio_edid_info);
  _(WSDISPLAYIO_SET_POLLING, WRITE, sizeof(int));
  _(WSDISPLAYIO_GET_FBINFO, READWRITE, struct wsdisplayio_fbinfo);
  _(WSDISPLAYIO_DOBLIT, READWRITE, struct wsdisplayio_blit);
  _(WSDISPLAYIO_WAITBLIT, READWRITE, struct wsdisplayio_blit);
  /* Entries from file: dev/biovar.h */
  _(BIOCLOCATE, READWRITE, struct bio_locate);
  _(BIOCINQ, READWRITE, struct bioc_inq);
  _(BIOCDISK_NOVOL, READWRITE, struct bioc_disk);
  _(BIOCDISK, READWRITE, struct bioc_disk);
  _(OBIOCDISK, READWRITE, struct obioc_disk);
  _(BIOCVOL, READWRITE, struct bioc_vol);
  _(OBIOCVOL, READWRITE, struct obioc_vol);
  _(BIOCALARM, READWRITE, struct bioc_alarm);
  _(BIOCBLINK, READWRITE, struct bioc_blink);
  _(BIOCSETSTATE, READWRITE, struct bioc_setstate);
  _(BIOCVOLOPS, READWRITE, struct bioc_volops);
  /* Entries from file: dev/md.h */
  _(MD_GETCONF, READ, struct md_conf);
  _(MD_SETCONF, WRITE, struct md_conf);
  /* Entries from file: dev/ccdvar.h */
  _(CCDIOCSET, READWRITE, struct ccd_ioctl);
  _(CCDIOCCLR, WRITE, struct ccd_ioctl);
  /* Entries from file: dev/cgdvar.h */
  _(CGDIOCSET, READWRITE, struct cgd_ioctl);
  _(CGDIOCCLR, WRITE, struct cgd_ioctl);
  _(CGDIOCGET, READWRITE, struct cgd_user);
  /* Entries from file: dev/fssvar.h */
  _(FSSIOCSET, WRITE, struct fss_set);
  _(FSSIOCGET, READ, struct fss_get);
  _(FSSIOCCLR, NONE);
  _(FSSIOFSET, WRITE, sizeof(int));
  _(FSSIOFGET, READ, sizeof(int));
  /* Entries from file: dev/bluetooth/btdev.h */
  _(BTDEV_ATTACH, WRITE, struct plistref);
  _(BTDEV_DETACH, WRITE, struct plistref);
  /* Entries from file: dev/bluetooth/btsco.h */
  _(BTSCO_GETINFO, READ, struct btsco_info);
  /* Entries from file: dev/kttcpio.h */
  _(KTTCP_IO_SEND, READWRITE, struct kttcp_io_args);
  _(KTTCP_IO_RECV, READWRITE, struct kttcp_io_args);
  /* Entries from file: dev/lockstat.h */
  _(IOC_LOCKSTAT_GVERSION, READ, sizeof(int));
  _(IOC_LOCKSTAT_ENABLE, WRITE, lsenable_t);
  _(IOC_LOCKSTAT_DISABLE, READ, lsdisable_t);
  /* Entries from file: dev/vndvar.h */
  _(VNDIOCSET, READWRITE, struct vnd_ioctl);
  _(VNDIOCCLR, WRITE, struct vnd_ioctl);
  _(VNDIOCGET, READWRITE, struct vnd_user);
  /* Entries from file: dev/spkrio.h */
  _(SPKRTONE, WRITE, tone_t);
  _(SPKRTUNE, NONE);
  _(SPKRGETVOL, READ, u_int);
  _(SPKRSETVOL, WRITE, u_int);
  /* Entries from file: net/bpf.h */
  _(BIOCGBLEN, READ, u_int);
  _(BIOCSBLEN, READWRITE, u_int);
  _(BIOCSETF, WRITE, struct bpf_program);
  _(BIOCFLUSH, NONE);
  _(BIOCPROMISC, NONE);
  _(BIOCGDLT, READ, u_int);
  _(BIOCGETIF, READ, struct ifreq);
  _(BIOCSETIF, WRITE, struct ifreq);
  _(BIOCSORTIMEOUT, WRITE, struct timeval50);
  _(BIOCGORTIMEOUT, READ, struct timeval50);
  _(BIOCGSTATS, READ, struct bpf_stat);
  _(BIOCGSTATSOLD, READ, struct bpf_stat_old);
  _(BIOCIMMEDIATE, WRITE, u_int);
  _(BIOCVERSION, READ, struct bpf_version);
  _(BIOCSTCPF, WRITE, struct bpf_program);
  _(BIOCSUDPF, WRITE, struct bpf_program);
  _(BIOCGHDRCMPLT, READ, u_int);
  _(BIOCSHDRCMPLT, WRITE, u_int);
  _(BIOCSDLT, WRITE, u_int);
  _(BIOCGDLTLIST, READWRITE, struct bpf_dltlist);
  _(BIOCGSEESENT, READ, u_int);
  _(BIOCSSEESENT, WRITE, u_int);
  _(BIOCSRTIMEOUT, WRITE, struct timeval);
  _(BIOCGRTIMEOUT, READ, struct timeval);
  _(BIOCGFEEDBACK, READ, u_int);
  _(BIOCSFEEDBACK, WRITE, u_int);
  /* Entries from file: net/if_atm.h */
  _(SIOCRAWATM, READWRITE, sizeof(int));
  _(SIOCATMENA, READWRITE, struct atm_pseudoioctl);
  _(SIOCATMDIS, READWRITE, struct atm_pseudoioctl);
  _(SIOCSPVCTX, READWRITE, struct pvctxreq);
  _(SIOCGPVCTX, READWRITE, struct pvctxreq);
  _(SIOCSPVCSIF, READWRITE, struct ifreq);
  _(SIOCGPVCSIF, READWRITE, struct ifreq);
  /* Entries from file: net/if_gre.h */
  _(GRESADDRS, WRITE, struct ifreq);
  _(GRESADDRD, WRITE, struct ifreq);
  _(GREGADDRS, READWRITE, struct ifreq);
  _(GREGADDRD, READWRITE, struct ifreq);
  _(GRESPROTO, WRITE, struct ifreq);
  _(GREGPROTO, READWRITE, struct ifreq);
  _(GRESSOCK, WRITE, struct ifreq);
  _(GREDSOCK, WRITE, struct ifreq);
  /* Entries from file: net/if_ppp.h */
  _(PPPIOCGRAWIN, READ, struct ppp_rawin);
  _(PPPIOCGFLAGS, READ, sizeof(int));
  _(PPPIOCSFLAGS, WRITE, sizeof(int));
  _(PPPIOCGASYNCMAP, READ, sizeof(int));
  _(PPPIOCSASYNCMAP, WRITE, sizeof(int));
  _(PPPIOCGUNIT, READ, sizeof(int));
  _(PPPIOCGRASYNCMAP, READ, sizeof(int));
  _(PPPIOCSRASYNCMAP, WRITE, sizeof(int));
  _(PPPIOCGMRU, READ, sizeof(int));
  _(PPPIOCSMRU, WRITE, sizeof(int));
  _(PPPIOCSMAXCID, WRITE, sizeof(int));
  _(PPPIOCGXASYNCMAP, READ, ext_accm);
  _(PPPIOCSXASYNCMAP, WRITE, ext_accm);
  _(PPPIOCXFERUNIT, NONE);
  _(PPPIOCSCOMPRESS, WRITE, struct ppp_option_data);
  _(PPPIOCGNPMODE, READWRITE, struct npioctl);
  _(PPPIOCSNPMODE, WRITE, struct npioctl);
  _(PPPIOCGIDLE, READ, struct ppp_idle);
  _(PPPIOCSPASS, WRITE, struct bpf_program);
  _(PPPIOCSACTIVE, WRITE, struct bpf_program);
  _(PPPIOCSIPASS, WRITE, struct bpf_program);
  _(PPPIOCSOPASS, WRITE, struct bpf_program);
  _(PPPIOCSIACTIVE, WRITE, struct bpf_program);
  _(PPPIOCSOACTIVE, WRITE, struct bpf_program);
  _(PPPIOCGMTU, READ, sizeof(int));
  _(PPPIOCSMTU, WRITE, sizeof(int));
  _(SIOCGPPPSTATS, READWRITE, struct ifpppstatsreq);
  _(SIOCGPPPCSTATS, READWRITE, struct ifpppcstatsreq);
  /* Entries from file: net/npf.h */
  _(IOC_NPF_VERSION, READ, sizeof(int));
  _(IOC_NPF_SWITCH, WRITE, sizeof(int));
  _(IOC_NPF_LOAD, READWRITE, struct plistref);
  _(IOC_NPF_TABLE, WRITE, struct npf_ioctl_table);
  _(IOC_NPF_STATS, WRITE, void);
  _(IOC_NPF_SAVE, READ, struct plistref);
  _(IOC_NPF_RULE, READWRITE, struct plistref);
  _(IOC_NPF_CONN_LOOKUP, READWRITE, struct plistref);
  /* Entries from file: net/if_pppoe.h */
  _(PPPOESETPARMS, WRITE, struct pppoediscparms);
  _(PPPOEGETPARMS, READWRITE, struct pppoediscparms);
  _(PPPOEGETSESSION, READWRITE, struct pppoeconnectionstate);
  /* Entries from file: net/if_sppp.h */
  _(SPPPGETAUTHCFG, READWRITE, struct spppauthcfg);
  _(SPPPSETAUTHCFG, WRITE, struct spppauthcfg);
  _(SPPPGETLCPCFG, READWRITE, struct sppplcpcfg);
  _(SPPPSETLCPCFG, WRITE, struct sppplcpcfg);
  _(SPPPGETSTATUS, READWRITE, struct spppstatus);
  _(SPPPGETSTATUSNCP, READWRITE, struct spppstatusncp);
  _(SPPPGETIDLETO, READWRITE, struct spppidletimeout);
  _(SPPPSETIDLETO, WRITE, struct spppidletimeout);
  _(SPPPGETAUTHFAILURES, READWRITE, struct spppauthfailurestats);
  _(SPPPSETAUTHFAILURE, WRITE, struct spppauthfailuresettings);
  _(SPPPSETDNSOPTS, WRITE, struct spppdnssettings);
  _(SPPPGETDNSOPTS, READWRITE, struct spppdnssettings);
  _(SPPPGETDNSADDRS, READWRITE, struct spppdnsaddrs);
  _(SPPPSETKEEPALIVE, WRITE, struct spppkeepalivesettings);
  _(SPPPGETKEEPALIVE, READWRITE, struct spppkeepalivesettings);
  /* Entries from file: net/if_srt.h */
  _(SRT_GETNRT, READ, unsigned int);
  _(SRT_GETRT, READWRITE, struct srt_rt);
  _(SRT_SETRT, WRITE, struct srt_rt);
  _(SRT_DELRT, WRITE, unsigned int);
  _(SRT_SFLAGS, WRITE, unsigned int);
  _(SRT_GFLAGS, READ, unsigned int);
  _(SRT_SGFLAGS, READWRITE, unsigned int);
  _(SRT_DEBUG, WRITE, void);
  /* Entries from file: net/if_tap.h */
  _(TAPGIFNAME, READ, struct ifreq);
  /* Entries from file: net/if_tun.h */
  _(TUNSDEBUG, WRITE, sizeof(int));
  _(TUNGDEBUG, READ, sizeof(int));
  _(TUNSIFMODE, WRITE, sizeof(int));
  _(TUNSLMODE, WRITE, sizeof(int));
  _(TUNSIFHEAD, WRITE, sizeof(int));
  _(TUNGIFHEAD, READ, sizeof(int));
  /* Entries from file: net/pfvar.h */
  _(DIOCSTART, NONE);
  _(DIOCSTOP, NONE);
  _(DIOCADDRULE, READWRITE, struct pfioc_rule);
  _(DIOCGETRULES, READWRITE, struct pfioc_rule);
  _(DIOCGETRULE, READWRITE, struct pfioc_rule);
  _(DIOCSETLCK, READWRITE, uint32_t);
  _(DIOCCLRSTATES, READWRITE, struct pfioc_state_kill);
  _(DIOCGETSTATE, READWRITE, struct pfioc_state);
  _(DIOCSETSTATUSIF, READWRITE, struct pfioc_if);
  _(DIOCGETSTATUS, READWRITE, struct pf_status);
  _(DIOCCLRSTATUS, NONE);
  _(DIOCNATLOOK, READWRITE, struct pfioc_natlook);
  _(DIOCSETDEBUG, READWRITE, u_int32_t);
  _(DIOCGETSTATES, READWRITE, struct pfioc_states);
  _(DIOCCHANGERULE, READWRITE, struct pfioc_rule);
  _(DIOCSETTIMEOUT, READWRITE, struct pfioc_tm);
  _(DIOCGETTIMEOUT, READWRITE, struct pfioc_tm);
  _(DIOCADDSTATE, READWRITE, struct pfioc_state);
  _(DIOCCLRRULECTRS, NONE);
  _(DIOCGETLIMIT, READWRITE, struct pfioc_limit);
  _(DIOCSETLIMIT, READWRITE, struct pfioc_limit);
  _(DIOCKILLSTATES, READWRITE, struct pfioc_state_kill);
  _(DIOCSTARTALTQ, NONE);
  _(DIOCSTOPALTQ, NONE);
  _(DIOCADDALTQ, READWRITE, struct pfioc_altq);
  _(DIOCGETALTQS, READWRITE, struct pfioc_altq);
  _(DIOCGETALTQ, READWRITE, struct pfioc_altq);
  _(DIOCCHANGEALTQ, READWRITE, struct pfioc_altq);
  _(DIOCGETQSTATS, READWRITE, struct pfioc_qstats);
  _(DIOCBEGINADDRS, READWRITE, struct pfioc_pooladdr);
  _(DIOCADDADDR, READWRITE, struct pfioc_pooladdr);
  _(DIOCGETADDRS, READWRITE, struct pfioc_pooladdr);
  _(DIOCGETADDR, READWRITE, struct pfioc_pooladdr);
  _(DIOCCHANGEADDR, READWRITE, struct pfioc_pooladdr);
  _(DIOCADDSTATES, READWRITE, struct pfioc_states);
  _(DIOCGETRULESETS, READWRITE, struct pfioc_ruleset);
  _(DIOCGETRULESET, READWRITE, struct pfioc_ruleset);
  _(DIOCRCLRTABLES, READWRITE, struct pfioc_table);
  _(DIOCRADDTABLES, READWRITE, struct pfioc_table);
  _(DIOCRDELTABLES, READWRITE, struct pfioc_table);
  _(DIOCRGETTABLES, READWRITE, struct pfioc_table);
  _(DIOCRGETTSTATS, READWRITE, struct pfioc_table);
  _(DIOCRCLRTSTATS, READWRITE, struct pfioc_table);
  _(DIOCRCLRADDRS, READWRITE, struct pfioc_table);
  _(DIOCRADDADDRS, READWRITE, struct pfioc_table);
  _(DIOCRDELADDRS, READWRITE, struct pfioc_table);
  _(DIOCRSETADDRS, READWRITE, struct pfioc_table);
  _(DIOCRGETADDRS, READWRITE, struct pfioc_table);
  _(DIOCRGETASTATS, READWRITE, struct pfioc_table);
  _(DIOCRCLRASTATS, READWRITE, struct pfioc_table);
  _(DIOCRTSTADDRS, READWRITE, struct pfioc_table);
  _(DIOCRSETTFLAGS, READWRITE, struct pfioc_table);
  _(DIOCRINADEFINE, READWRITE, struct pfioc_table);
  _(DIOCOSFPFLUSH, NONE);
  _(DIOCOSFPADD, READWRITE, struct pf_osfp_ioctl);
  _(DIOCOSFPGET, READWRITE, struct pf_osfp_ioctl);
  _(DIOCXBEGIN, READWRITE, struct pfioc_trans);
  _(DIOCXCOMMIT, READWRITE, struct pfioc_trans);
  _(DIOCXROLLBACK, READWRITE, struct pfioc_trans);
  _(DIOCGETSRCNODES, READWRITE, struct pfioc_src_nodes);
  _(DIOCCLRSRCNODES, NONE);
  _(DIOCSETHOSTID, READWRITE, u_int32_t);
  _(DIOCIGETIFACES, READWRITE, struct pfioc_iface);
  _(DIOCSETIFFLAG, READWRITE, struct pfioc_iface);
  _(DIOCCLRIFFLAG, READWRITE, struct pfioc_iface);
  _(DIOCKILLSRCNODES, READWRITE, struct pfioc_src_node_kill);
  /* Entries from file: net/slip.h */
  _(SLIOCGUNIT, READ, sizeof(int));
  /* Entries from file: netbt/hci.h */
  _(SIOCGBTINFO, READWRITE, struct btreq);
  _(SIOCGBTINFOA, READWRITE, struct btreq);
  _(SIOCNBTINFO, READWRITE, struct btreq);
  _(SIOCSBTFLAGS, READWRITE, struct btreq);
  _(SIOCSBTPOLICY, READWRITE, struct btreq);
  _(SIOCSBTPTYPE, READWRITE, struct btreq);
  _(SIOCGBTSTATS, READWRITE, struct btreq);
  _(SIOCZBTSTATS, READWRITE, struct btreq);
  _(SIOCBTDUMP, WRITE, struct btreq);
  _(SIOCSBTSCOMTU, READWRITE, struct btreq);
  _(SIOCGBTFEAT, READWRITE, struct btreq);
  /* Entries from file: netinet/ip_nat.h */
  _(SIOCADNAT, WRITE, struct ipfobj);
  _(SIOCRMNAT, WRITE, struct ipfobj);
  _(SIOCGNATS, READWRITE, struct ipfobj);
  _(SIOCGNATL, READWRITE, struct ipfobj);
  _(SIOCPURGENAT, READWRITE, struct ipfobj);
  _(SIOCADNAT, WRITE, struct ipfobj);
  _(SIOCRMNAT, WRITE, struct ipfobj);
  _(SIOCGNATS, READWRITE, struct ipfobj);
  _(SIOCGNATL, READWRITE, struct ipfobj);
  _(SIOCPURGENAT, READWRITE, struct ipfobj);
  /* Entries from file: netinet/ip_proxy.h */
  _(SIOCPROXY, READWRITE, struct ap_control);
  _(SIOCPROXY, READWRITE, struct ap_control);
  /* Entries from file: netinet6/in6_var.h */
  _(SIOCSIFINFO_FLAGS, READWRITE, struct in6_ndireq);
  _(SIOCAADDRCTL_POLICY, WRITE, struct in6_addrpolicy);
  _(SIOCDADDRCTL_POLICY, WRITE, struct in6_addrpolicy);
  /* Entries from file: netnatm/natm.h */
  _(SIOCXRAWATM, READWRITE, struct atm_rawioctl);
  /* Entries from file: netsmb/smb_dev.h */
  _(SMBIOC_OPENSESSION, WRITE, struct smbioc_ossn);
  _(SMBIOC_OPENSHARE, WRITE, struct smbioc_oshare);
  _(SMBIOC_REQUEST, READWRITE, struct smbioc_rq);
  _(SMBIOC_SETFLAGS, WRITE, struct smbioc_flags);
  _(SMBIOC_LOOKUP, WRITE, struct smbioc_lookup);
  _(SMBIOC_READ, READWRITE, struct smbioc_rw);
  _(SMBIOC_WRITE, READWRITE, struct smbioc_rw);
  /* Entries from file: sys/agpio.h */
  _(AGPIOC_INFO, READ, agp_info);
  _(AGPIOC_ACQUIRE, NONE);
  _(AGPIOC_RELEASE, NONE);
  _(AGPIOC_SETUP, WRITE, agp_setup);
  _(AGPIOC_RESERVE, WRITE, agp_region);
  _(AGPIOC_PROTECT, WRITE, agp_region);
  _(AGPIOC_ALLOCATE, READWRITE, agp_allocate);
  _(AGPIOC_DEALLOCATE, WRITE, sizeof(int));
  _(AGPIOC_BIND, WRITE, agp_bind);
  _(AGPIOC_UNBIND, WRITE, agp_unbind);
  /* Entries from file: sys/audioio.h */
  _(AUDIO_GETINFO, READ, struct audio_info);
  _(AUDIO_SETINFO, READWRITE, struct audio_info);
  _(AUDIO_DRAIN, NONE);
  _(AUDIO_FLUSH, NONE);
  _(AUDIO_WSEEK, READ, u_long);
  _(AUDIO_RERROR, READ, sizeof(int));
  _(AUDIO_GETDEV, READ, struct audio_device);
  _(AUDIO_GETENC, READWRITE, struct audio_encoding);
  _(AUDIO_GETFD, READ, sizeof(int));
  _(AUDIO_SETFD, READWRITE, sizeof(int));
  _(AUDIO_PERROR, READ, sizeof(int));
  _(AUDIO_GETIOFFS, READ, struct audio_offset);
  _(AUDIO_GETOOFFS, READ, struct audio_offset);
  _(AUDIO_GETPROPS, READ, sizeof(int));
  _(AUDIO_GETBUFINFO, READ, struct audio_info);
  _(AUDIO_SETCHAN, WRITE, sizeof(int));
  _(AUDIO_GETCHAN, READ, sizeof(int));
  _(AUDIO_MIXER_READ, READWRITE, mixer_ctrl_t);
  _(AUDIO_MIXER_WRITE, READWRITE, mixer_ctrl_t);
  _(AUDIO_MIXER_DEVINFO, READWRITE, mixer_devinfo_t);
  /* Entries from file: sys/ataio.h */
  _(ATAIOCCOMMAND, READWRITE, atareq_t);
  _(ATABUSIOSCAN, WRITE, struct atabusioscan_args);
  _(ATABUSIORESET, NONE);
  _(ATABUSIODETACH, WRITE, struct atabusiodetach_args);
  /* Entries from file: sys/cdio.h */
  _(CDIOCPLAYTRACKS, WRITE, struct ioc_play_track);
  _(CDIOCPLAYBLOCKS, WRITE, struct ioc_play_blocks);
  _(CDIOCREADSUBCHANNEL, READWRITE, struct ioc_read_subchannel);
  _(CDIOCREADSUBCHANNEL_BUF, READWRITE, struct ioc_read_subchannel_buf);
  _(CDIOREADTOCHEADER, READ, struct ioc_toc_header);
  _(CDIOREADTOCENTRIES, READWRITE, struct ioc_read_toc_entry);
  _(CDIOREADTOCENTRIES_BUF, READWRITE, struct ioc_read_toc_entry_buf);
  _(CDIOREADMSADDR, READWRITE, sizeof(int));
  _(CDIOCSETPATCH, WRITE, struct ioc_patch);
  _(CDIOCGETVOL, READ, struct ioc_vol);
  _(CDIOCSETVOL, WRITE, struct ioc_vol);
  _(CDIOCSETMONO, NONE);
  _(CDIOCSETSTEREO, NONE);
  _(CDIOCSETMUTE, NONE);
  _(CDIOCSETLEFT, NONE);
  _(CDIOCSETRIGHT, NONE);
  _(CDIOCSETDEBUG, NONE);
  _(CDIOCCLRDEBUG, NONE);
  _(CDIOCPAUSE, NONE);
  _(CDIOCRESUME, NONE);
  _(CDIOCRESET, NONE);
  _(CDIOCSTART, NONE);
  _(CDIOCSTOP, NONE);
  _(CDIOCEJECT, NONE);
  _(CDIOCALLOW, NONE);
  _(CDIOCPREVENT, NONE);
  _(CDIOCCLOSE, NONE);
  _(CDIOCPLAYMSF, WRITE, struct ioc_play_msf);
  _(CDIOCLOADUNLOAD, WRITE, struct ioc_load_unload);
  _(MMCGETDISCINFO, READ, struct mmc_discinfo);
  _(MMCGETTRACKINFO, READWRITE, struct mmc_trackinfo);
  _(MMCOP, READWRITE, struct mmc_op);
  _(MMCSETUPWRITEPARAMS, WRITE, struct mmc_writeparams);
  /* Entries from file: sys/chio.h */
  _(CHIOMOVE, WRITE, struct changer_move_request);
  _(CHIOEXCHANGE, WRITE, struct changer_exchange_request);
  _(CHIOPOSITION, WRITE, struct changer_position_request);
  _(CHIOGPICKER, READ, sizeof(int));
  _(CHIOSPICKER, WRITE, sizeof(int));
  _(CHIOGPARAMS, READ, struct changer_params);
  _(CHIOIELEM, NONE);
  _(OCHIOGSTATUS, WRITE, struct ochanger_element_status_request);
  _(CHIOGSTATUS, WRITE, struct changer_element_status_request);
  _(CHIOSVOLTAG, WRITE, struct changer_set_voltag_request);
  /* Entries from file: sys/clockctl.h */
  _(CLOCKCTL_SETTIMEOFDAY, WRITE, struct clockctl_settimeofday);
  _(CLOCKCTL_ADJTIME, READWRITE, struct clockctl_adjtime);
  _(CLOCKCTL_CLOCK_SETTIME, WRITE, struct clockctl_clock_settime);
  _(CLOCKCTL_NTP_ADJTIME, READWRITE, struct clockctl_ntp_adjtime);
  /* Entries from file: sys/cpuio.h */
  _(IOC_CPU_SETSTATE, WRITE, cpustate_t);
  _(IOC_CPU_GETSTATE, READWRITE, cpustate_t);
  _(IOC_CPU_GETCOUNT, READ, sizeof(int));
  _(IOC_CPU_MAPID, READWRITE, sizeof(int));
  _(IOC_CPU_UCODE_GET_VERSION, READWRITE, struct cpu_ucode_version);
  _(IOC_CPU_UCODE_APPLY, WRITE, struct cpu_ucode);
  /* Entries from file: sys/dkio.h */
  _(DIOCGDINFO, READ, struct disklabel);
  _(DIOCSDINFO, WRITE, struct disklabel);
  _(DIOCWDINFO, WRITE);
  _(DIOCGPARTINFO, WRITE, struct partinfo);
  _(ODIOCGDINFO, READ, struct olddisklabel);
  _(ODIOCSDINFO, WRITE, struct olddisklabel);
  _(ODIOCWDINFO, WRITE);
  _(DIOCRFORMAT, READWRITE, struct format_op);
  _(DIOCWFORMAT, READWRITE, struct format_op);
  _(DIOCSSTEP, WRITE, sizeof(int));
  _(DIOCSRETRIES, WRITE, sizeof(int));
  _(DIOCKLABEL, WRITE, sizeof(int));
  _(DIOCWLABEL, WRITE, sizeof(int));
  _(DIOCSBAD, WRITE, struct dkbad);
  _(DIOCEJECT, WRITE, sizeof(int));
  _(ODIOCEJECT, NONE);
  _(DIOCLOCK, WRITE, sizeof(int));
  _(DIOCGDEFLABEL, READ, struct disklabel);
  _(DIOCCLRLABEL, NONE);
  _(ODIOCGDEFLABEL, READ, struct olddisklabel);
  _(DIOCGCACHE, READ, sizeof(int));
  _(DIOCSCACHE, WRITE, sizeof(int));
  _(DIOCCACHESYNC, WRITE, sizeof(int));
  _(DIOCBSLIST, READWRITE, struct disk_badsecinfo);
  _(DIOCBSFLUSH, NONE);
  _(DIOCAWEDGE, READWRITE, struct dkwedge_info);
  _(DIOCGWEDGEINFO, READ, struct dkwedge_info);
  _(DIOCDWEDGE, WRITE, struct dkwedge_info);
  _(DIOCLWEDGES, READWRITE, struct dkwedge_list);
  _(DIOCGSTRATEGY, READ, struct disk_strategy);
  _(DIOCSSTRATEGY, WRITE, struct disk_strategy);
  _(DIOCGDISKINFO, READ, struct plistref);
  _(DIOCTUR, READ, sizeof(int));
  _(DIOCMWEDGES, READ, sizeof(int));
  _(DIOCGSECTORSIZE, READ, u_int);
  _(DIOCGMEDIASIZE, READ, off_t);
  /* Entries from file: sys/drvctlio.h */
  _(DRVDETACHDEV, WRITE, struct devdetachargs);
  _(DRVRESCANBUS, WRITE, struct devrescanargs);
  _(DRVCTLCOMMAND, READWRITE, struct plistref);
  _(DRVRESUMEDEV, WRITE, struct devpmargs);
  _(DRVLISTDEV, READWRITE, struct devlistargs);
  _(DRVGETEVENT, READ, struct plistref);
  _(DRVSUSPENDDEV, WRITE, struct devpmargs);
  /* Entries from file: sys/dvdio.h */
  _(DVD_READ_STRUCT, READWRITE, dvd_struct);
  _(DVD_WRITE_STRUCT, READWRITE, dvd_struct);
  _(DVD_AUTH, READWRITE, dvd_authinfo);
  /* Entries from file: sys/envsys.h */
  _(ENVSYS_GETDICTIONARY, READWRITE, struct plistref);
  _(ENVSYS_SETDICTIONARY, READWRITE, struct plistref);
  _(ENVSYS_REMOVEPROPS, READWRITE, struct plistref);
  _(ENVSYS_GTREDATA, READWRITE, envsys_tre_data_t);
  _(ENVSYS_GTREINFO, READWRITE, envsys_basic_info_t);
  /* Entries from file: sys/event.h */
  _(KFILTER_BYFILTER, READWRITE, struct kfilter_mapping);
  _(KFILTER_BYNAME, READWRITE, struct kfilter_mapping);
  /* Entries from file: sys/fdio.h */
  _(FDIOCGETOPTS, READ);
  _(FDIOCSETOPTS, WRITE, sizeof(int));
  _(FDIOCSETFORMAT, WRITE, struct fdformat_parms);
  _(FDIOCGETFORMAT, READ, struct fdformat_parms);
  _(FDIOCFORMAT_TRACK, WRITE, struct fdformat_cmd);
  /* Entries from file: sys/filio.h */
  _(FIOCLEX, NONE);
  _(FIONCLEX, NONE);
  _(FIONREAD, READ, sizeof(int));
  _(FIONBIO, WRITE, sizeof(int));
  _(FIOASYNC, WRITE, sizeof(int));
  _(FIOSETOWN, WRITE, sizeof(int));
  _(FIOGETOWN, READ, sizeof(int));
  _(OFIOGETBMAP, READWRITE, uint32_t);
  _(FIOGETBMAP, READWRITE, daddr_t);
  _(FIONWRITE, READ, sizeof(int));
  _(FIONSPACE, READ, sizeof(int));
  /* Entries from file: sys/gpio.h */
  _(GPIOINFO, READ, struct gpio_info);
  _(GPIOSET, READWRITE, struct gpio_set);
  _(GPIOUNSET, READWRITE, struct gpio_set);
  _(GPIOREAD, READWRITE, struct gpio_req);
  _(GPIOWRITE, READWRITE, struct gpio_req);
  _(GPIOTOGGLE, READWRITE, struct gpio_req);
  _(GPIOATTACH, READWRITE, struct gpio_attach);
  _(GPIOPINREAD, READWRITE, struct gpio_pin_op);
  _(GPIOPINWRITE, READWRITE, struct gpio_pin_op);
  _(GPIOPINTOGGLE, READWRITE, struct gpio_pin_op);
  _(GPIOPINCTL, READWRITE, struct gpio_pin_ctl);
  _(GPIODETACH, READWRITE, struct gpio_attach);
  /* Entries from file: sys/ioctl.h */
  _(PTIOCNETBSD, WRITE, struct ioctl_pt);
  _(PTIOCSUNOS, WRITE, struct ioctl_pt);
  _(PTIOCLINUX, WRITE, struct ioctl_pt);
  _(PTIOCFREEBSD, WRITE, struct ioctl_pt);
  _(PTIOCULTRIX, WRITE, struct ioctl_pt);
  /* Entries from file: sys/ioctl_compat.h */
  _(TIOCHPCL, NONE);
  _(TIOCGETP, READ, struct sgttyb);
  _(TIOCSETP, WRITE, struct sgttyb);
  _(TIOCSETN, WRITE);
  _(TIOCSETC, WRITE, struct tchars);
  _(TIOCGETC, READ, struct tchars);
  _(TIOCLBIS, WRITE, sizeof(int));
  _(TIOCLBIC, WRITE, sizeof(int));
  _(TIOCLSET, WRITE, sizeof(int));
  _(TIOCLGET, READ, sizeof(int));
  _(TIOCSLTC, WRITE, struct ltchars);
  _(TIOCGLTC, READ, struct ltchars);
  _(OTIOCCONS, NONE);
  /* Entries from file: sys/joystick.h */
  _(JOY_SETTIMEOUT, WRITE, sizeof(int));
  _(JOY_GETTIMEOUT, READ, sizeof(int));
  _(JOY_SET_X_OFFSET, WRITE, sizeof(int));
  _(JOY_SET_Y_OFFSET, WRITE, sizeof(int));
  _(JOY_GET_X_OFFSET, READ, sizeof(int));
  _(JOY_GET_Y_OFFSET, READ, sizeof(int));
  /* Entries from file: sys/ksyms.h */
  _(OKIOCGSYMBOL, WRITE, struct ksyms_ogsymbol);
  _(OKIOCGVALUE, WRITE, struct ksyms_ogsymbol);
  _(KIOCGSIZE, READ, sizeof(int));
  _(KIOCGVALUE, READWRITE, struct ksyms_gvalue);
  _(KIOCGSYMBOL, READWRITE, struct ksyms_gsymbol);
  /* Entries from file: sys/lua.h */
  _(LUAINFO, READWRITE, struct lua_info);
  _(LUACREATE, READWRITE, struct lua_create);
  _(LUADESTROY, READWRITE, struct lua_create);
  _(LUAREQUIRE, READWRITE, struct lua_require);
  _(LUALOAD, READWRITE, struct lua_load);
  /* Entries from file: sys/midiio.h */
  _(MIDI_PRETIME, READWRITE, sizeof(int));
  _(MIDI_MPUMODE, READWRITE, sizeof(int));
  _(MIDI_MPUCMD, READWRITE, mpu_command_rec);
  _(SEQUENCER_RESET, NONE);
  _(SEQUENCER_SYNC, NONE);
  _(SEQUENCER_INFO, READWRITE, struct synth_info);
  _(SEQUENCER_CTRLRATE, READWRITE, sizeof(int));
  _(SEQUENCER_GETOUTCOUNT, READ, sizeof(int));
  _(SEQUENCER_GETINCOUNT, READ, sizeof(int));
  _(SEQUENCER_PERCMODE, WRITE, sizeof(int));
  _(SEQUENCER_TESTMIDI, WRITE, sizeof(int));
  _(SEQUENCER_RESETSAMPLES, WRITE, sizeof(int));
  _(SEQUENCER_NRSYNTHS, READ, sizeof(int));
  _(SEQUENCER_NRMIDIS, READ, sizeof(int));
  _(SEQUENCER_MIDI_INFO, READWRITE, struct midi_info);
  _(SEQUENCER_THRESHOLD, WRITE, sizeof(int));
  _(SEQUENCER_MEMAVL, READWRITE, sizeof(int));
  _(SEQUENCER_PANIC, NONE);
  _(SEQUENCER_OUTOFBAND, WRITE, struct seq_event_rec);
  _(SEQUENCER_GETTIME, READ, sizeof(int));
  _(SEQUENCER_ID, READWRITE, struct synth_info);
  _(SEQUENCER_CONTROL, READWRITE, struct synth_control);
  _(SEQUENCER_REMOVESAMPLE, READWRITE, struct remove_sample);
  _(SEQUENCER_TMR_TIMEBASE, READWRITE, sizeof(int));
  _(SEQUENCER_TMR_START, NONE);
  _(SEQUENCER_TMR_STOP, NONE);
  _(SEQUENCER_TMR_CONTINUE, NONE);
  _(SEQUENCER_TMR_TEMPO, READWRITE, sizeof(int));
  _(SEQUENCER_TMR_SOURCE, READWRITE, sizeof(int));
  _(SEQUENCER_TMR_METRONOME, WRITE, sizeof(int));
  _(SEQUENCER_TMR_SELECT, WRITE, sizeof(int));
  /* Entries from file: sys/mtio.h */
  _(MTIOCTOP, WRITE, struct mtop);
  _(MTIOCGET, READ, struct mtget);
  _(MTIOCIEOT, NONE);
  _(MTIOCEEOT, NONE);
  _(MTIOCRDSPOS, READ, uint32_t);
  _(MTIOCRDHPOS, READ, uint32_t);
  _(MTIOCSLOCATE, WRITE, uint32_t);
  _(MTIOCHLOCATE, WRITE, uint32_t);
  /* Entries from file: sys/power.h */
  _(POWER_EVENT_RECVDICT, READWRITE, struct plistref);
  _(POWER_IOC_GET_TYPE, READ, struct power_type);
  _(POWER_IOC_GET_TYPE_WITH_LOSSAGE, READ, sizeof);
  /* Entries from file: sys/radioio.h */
  _(RIOCGINFO, READ, struct radio_info);
  _(RIOCSINFO, READWRITE, struct radio_info);
  _(RIOCSSRCH, WRITE, sizeof(int));
  /* Entries from file: sys/rndio.h */
  _(RNDGETENTCNT, READ, uint32_t);
  _(RNDGETSRCNUM, READWRITE, rndstat_t);
  _(RNDGETSRCNAME, READWRITE, rndstat_name_t);
  _(RNDCTL, WRITE, rndctl_t);
  _(RNDADDDATA, WRITE, rnddata_t);
  _(RNDGETPOOLSTAT, READ, rndpoolstat_t);
  _(RNDGETESTNUM, READWRITE, rndstat_est_t);
  _(RNDGETESTNAME, READWRITE, rndstat_est_name_t);
  /* Entries from file: sys/scanio.h */
  _(SCIOCGET, READ, struct scan_io);
  _(SCIOCSET, WRITE, struct scan_io);
  _(SCIOCRESTART, NONE);
  _(SCIOC_USE_ADF, NONE);
  /* Entries from file: sys/scsiio.h */
  _(SCIOCCOMMAND, READWRITE, scsireq_t);
  _(SCIOCDEBUG, WRITE, sizeof(int));
  _(SCIOCIDENTIFY, READ, struct scsi_addr);
  _(OSCIOCIDENTIFY, READ, struct oscsi_addr);
  _(SCIOCDECONFIG, NONE);
  _(SCIOCRECONFIG, NONE);
  _(SCIOCRESET, NONE);
  _(SCBUSIOSCAN, WRITE, struct scbusioscan_args);
  _(SCBUSIORESET, NONE);
  _(SCBUSIODETACH, WRITE, struct scbusiodetach_args);
  _(SCBUSACCEL, WRITE, struct scbusaccel_args);
  _(SCBUSIOLLSCAN, NONE);
  /* Entries from file: sys/sockio.h */
  _(SIOCSHIWAT, WRITE, sizeof(int));
  _(SIOCGHIWAT, READ, sizeof(int));
  _(SIOCSLOWAT, WRITE, sizeof(int));
  _(SIOCGLOWAT, READ, sizeof(int));
  _(SIOCATMARK, READ, sizeof(int));
  _(SIOCSPGRP, WRITE, sizeof(int));
  _(SIOCGPGRP, READ, sizeof(int));
  _(SIOCADDRT, WRITE, struct ortentry);
  _(SIOCDELRT, WRITE, struct ortentry);
  _(SIOCSIFADDR, WRITE, struct ifreq);
  _(SIOCGIFADDR, READWRITE, struct ifreq);
  _(SIOCSIFDSTADDR, WRITE, struct ifreq);
  _(SIOCGIFDSTADDR, READWRITE, struct ifreq);
  _(SIOCSIFFLAGS, WRITE, struct ifreq);
  _(SIOCGIFFLAGS, READWRITE, struct ifreq);
  _(SIOCGIFBRDADDR, READWRITE, struct ifreq);
  _(SIOCSIFBRDADDR, WRITE, struct ifreq);
  _(SIOCGIFCONF, READWRITE, struct ifconf);
  _(SIOCGIFNETMASK, READWRITE, struct ifreq);
  _(SIOCSIFNETMASK, WRITE, struct ifreq);
  _(SIOCGIFMETRIC, READWRITE, struct ifreq);
  _(SIOCSIFMETRIC, WRITE, struct ifreq);
  _(SIOCDIFADDR, WRITE, struct ifreq);
  _(SIOCAIFADDR, WRITE, struct ifaliasreq);
  _(SIOCGIFALIAS, READWRITE, struct ifaliasreq);
  _(SIOCGIFAFLAG_IN, READWRITE, struct ifreq);
  _(SIOCALIFADDR, WRITE, struct if_laddrreq);
  _(SIOCGLIFADDR, READWRITE, struct if_laddrreq);
  _(SIOCDLIFADDR, WRITE, struct if_laddrreq);
  _(SIOCSIFADDRPREF, WRITE, struct if_addrprefreq);
  _(SIOCGIFADDRPREF, READWRITE, struct if_addrprefreq);
  _(SIOCADDMULTI, WRITE, struct ifreq);
  _(SIOCDELMULTI, WRITE, struct ifreq);
  _(SIOCGETVIFCNT, READWRITE, struct sioc_vif_req);
  _(SIOCGETSGCNT, READWRITE, struct sioc_sg_req);
  _(SIOCSIFMEDIA, READWRITE, struct ifreq);
  _(SIOCGIFMEDIA, READWRITE, struct ifmediareq);
  _(SIOCSIFGENERIC, WRITE, struct ifreq);
  _(SIOCGIFGENERIC, READWRITE, struct ifreq);
  _(SIOCSIFPHYADDR, WRITE, struct ifaliasreq);
  _(SIOCGIFPSRCADDR, READWRITE, struct ifreq);
  _(SIOCGIFPDSTADDR, READWRITE, struct ifreq);
  _(SIOCDIFPHYADDR, WRITE, struct ifreq);
  _(SIOCSLIFPHYADDR, WRITE, struct if_laddrreq);
  _(SIOCGLIFPHYADDR, READWRITE, struct if_laddrreq);
  _(SIOCSIFMTU, WRITE, struct ifreq);
  _(SIOCGIFMTU, READWRITE, struct ifreq);
  _(SIOCSDRVSPEC, WRITE, struct ifdrv);
  _(SIOCGDRVSPEC, READWRITE, struct ifdrv);
  _(SIOCIFCREATE, WRITE, struct ifreq);
  _(SIOCIFDESTROY, WRITE, struct ifreq);
  _(SIOCIFGCLONERS, READWRITE, struct if_clonereq);
  _(SIOCGIFDLT, READWRITE, struct ifreq);
  _(SIOCGIFCAP, READWRITE, struct ifcapreq);
  _(SIOCSIFCAP, WRITE, struct ifcapreq);
  _(SIOCSVH, READWRITE, struct ifreq);
  _(SIOCGVH, READWRITE, struct ifreq);
  _(SIOCINITIFADDR, READWRITE, struct ifaddr);
  _(SIOCGIFDATA, READWRITE, struct ifdatareq);
  _(SIOCZIFDATA, READWRITE, struct ifdatareq);
  _(SIOCGLINKSTR, READWRITE, struct ifdrv);
  _(SIOCSLINKSTR, WRITE, struct ifdrv);
  _(SIOCGETHERCAP, READWRITE, struct eccapreq);
  _(SIOCGIFINDEX, READWRITE, struct ifreq);
  _(SIOCSETPFSYNC, WRITE, struct ifreq);
  _(SIOCGETPFSYNC, READWRITE, struct ifreq);
  /* Entries from file: sys/timepps.h */
  _(PPS_IOC_CREATE, NONE);
  _(PPS_IOC_DESTROY, NONE);
  _(PPS_IOC_SETPARAMS, WRITE, pps_params_t);
  _(PPS_IOC_GETPARAMS, READ, pps_params_t);
  _(PPS_IOC_GETCAP, READ, sizeof(int));
  _(PPS_IOC_FETCH, READWRITE, pps_info_t);
  _(PPS_IOC_KCBIND, WRITE, sizeof(int));
  /* Entries from file: sys/ttycom.h */
  _(TIOCEXCL, NONE);
  _(TIOCNXCL, NONE);
  _(TIOCFLUSH, WRITE, sizeof(int));
  _(TIOCGETA, READ, struct termios);
  _(TIOCSETA, WRITE, struct termios);
  _(TIOCSETAW, WRITE);
  _(TIOCSETAF, WRITE);
  _(TIOCGETD, READ, sizeof(int));
  _(TIOCSETD, WRITE, sizeof(int));
  _(TIOCGLINED, READ, linedn_t);
  _(TIOCSLINED, WRITE, linedn_t);
  _(TIOCSBRK, NONE);
  _(TIOCCBRK, NONE);
  _(TIOCSDTR, NONE);
  _(TIOCCDTR, NONE);
  _(TIOCGPGRP, READ, sizeof(int));
  _(TIOCSPGRP, WRITE, sizeof(int));
  _(TIOCOUTQ, READ, sizeof(int));
  _(TIOCSTI, WRITE, char);
  _(TIOCNOTTY, NONE);
  _(TIOCPKT, WRITE, sizeof(int));
  _(TIOCSTOP, NONE, like);
  _(TIOCSTART, NONE, like);
  _(TIOCMSET, WRITE, sizeof(int));
  _(TIOCMBIS, WRITE, sizeof(int));
  _(TIOCMBIC, WRITE, sizeof(int));
  _(TIOCMGET, READ, sizeof(int));
  _(TIOCREMOTE, WRITE, sizeof(int));
  _(TIOCGWINSZ, READ, struct winsize);
  _(TIOCSWINSZ, WRITE, struct winsize);
  _(TIOCUCNTL, WRITE, sizeof(int));
  _(TIOCSTAT, WRITE, sizeof(int));
  _(TIOCGSID, READ, sizeof(int));
  _(TIOCCONS, WRITE, sizeof(int));
  _(TIOCSCTTY, NONE);
  _(TIOCEXT, WRITE, sizeof(int));
  _(TIOCSIG, NONE);
  _(TIOCDRAIN, NONE);
  _(TIOCGFLAGS, READ, sizeof(int));
  _(TIOCSFLAGS, WRITE, sizeof(int));
  _(TIOCDCDTIMESTAMP, READ, struct timeval);
  _(TIOCRCVFRAME, WRITE, struct mbuf);
  _(TIOCXMTFRAME, WRITE, struct mbuf);
  _(TIOCPTMGET, READ, struct ptmget);
  _(TIOCGRANTPT, NONE);
  _(TIOCPTSNAME, READ, struct ptmget);
  _(TIOCSQSIZE, WRITE, sizeof(int));
  _(TIOCGQSIZE, READ, sizeof(int));
  /* Entries from file: sys/verified_exec.h */
  _(VERIEXEC_LOAD, WRITE, struct plistref);
  _(VERIEXEC_TABLESIZE, WRITE, struct plistref);
  _(VERIEXEC_DELETE, WRITE, struct plistref);
  _(VERIEXEC_QUERY, READWRITE, struct plistref);
  _(VERIEXEC_DUMP, READ, struct plistref);
  _(VERIEXEC_FLUSH, NONE);
  /* Entries from file: sys/videoio.h */
  _(VIDIOC_QUERYCAP, READ, struct v4l2_capability);
  _(VIDIOC_RESERVED, NONE);
  _(VIDIOC_ENUM_FMT, READWRITE, struct v4l2_fmtdesc);
  _(VIDIOC_G_FMT, READWRITE, struct v4l2_format);
  _(VIDIOC_S_FMT, READWRITE, struct v4l2_format);
  _(VIDIOC_REQBUFS, READWRITE, struct v4l2_requestbuffers);
  _(VIDIOC_QUERYBUF, READWRITE, struct v4l2_buffer);
  _(VIDIOC_G_FBUF, READ, struct v4l2_framebuffer);
  _(VIDIOC_S_FBUF, WRITE, struct v4l2_framebuffer);
  _(VIDIOC_OVERLAY, WRITE, sizeof(int));
  _(VIDIOC_QBUF, READWRITE, struct v4l2_buffer);
  _(VIDIOC_DQBUF, READWRITE, struct v4l2_buffer);
  _(VIDIOC_STREAMON, WRITE, sizeof(int));
  _(VIDIOC_STREAMOFF, WRITE, sizeof(int));
  _(VIDIOC_G_PARM, READWRITE, struct v4l2_streamparm);
  _(VIDIOC_S_PARM, READWRITE, struct v4l2_streamparm);
  _(VIDIOC_G_STD, READ, v4l2_std_id);
  _(VIDIOC_S_STD, WRITE, v4l2_std_id);
  _(VIDIOC_ENUMSTD, READWRITE, struct v4l2_standard);
  _(VIDIOC_ENUMINPUT, READWRITE, struct v4l2_input);
  _(VIDIOC_G_CTRL, READWRITE, struct v4l2_control);
  _(VIDIOC_S_CTRL, READWRITE, struct v4l2_control);
  _(VIDIOC_G_TUNER, READWRITE, struct v4l2_tuner);
  _(VIDIOC_S_TUNER, WRITE, struct v4l2_tuner);
  _(VIDIOC_G_AUDIO, READ, struct v4l2_audio);
  _(VIDIOC_S_AUDIO, WRITE, struct v4l2_audio);
  _(VIDIOC_QUERYCTRL, READWRITE, struct v4l2_queryctrl);
  _(VIDIOC_QUERYMENU, READWRITE, struct v4l2_querymenu);
  _(VIDIOC_G_INPUT, READ, sizeof(int));
  _(VIDIOC_S_INPUT, READWRITE, sizeof(int));
  _(VIDIOC_G_OUTPUT, READ, sizeof(int));
  _(VIDIOC_S_OUTPUT, READWRITE, sizeof(int));
  _(VIDIOC_ENUMOUTPUT, READWRITE, struct v4l2_output);
  _(VIDIOC_G_AUDOUT, READ, struct v4l2_audioout);
  _(VIDIOC_S_AUDOUT, WRITE, struct v4l2_audioout);
  _(VIDIOC_G_MODULATOR, READWRITE, struct v4l2_modulator);
  _(VIDIOC_S_MODULATOR, WRITE, struct v4l2_modulator);
  _(VIDIOC_G_FREQUENCY, READWRITE, struct v4l2_frequency);
  _(VIDIOC_S_FREQUENCY, WRITE, struct v4l2_frequency);
  _(VIDIOC_CROPCAP, READWRITE, struct v4l2_cropcap);
  _(VIDIOC_G_CROP, READWRITE, struct v4l2_crop);
  _(VIDIOC_S_CROP, WRITE, struct v4l2_crop);
  _(VIDIOC_G_JPEGCOMP, READ, struct v4l2_jpegcompression);
  _(VIDIOC_S_JPEGCOMP, WRITE, struct v4l2_jpegcompression);
  _(VIDIOC_QUERYSTD, READ, v4l2_std_id);
  _(VIDIOC_TRY_FMT, READWRITE, struct v4l2_format);
  _(VIDIOC_ENUMAUDIO, READWRITE, struct v4l2_audio);
  _(VIDIOC_ENUMAUDOUT, READWRITE, struct v4l2_audioout);
  _(VIDIOC_G_PRIORITY, READ, enum v4l2_priority);
  _(VIDIOC_S_PRIORITY, WRITE, enum v4l2_priority);
  _(VIDIOC_ENUM_FRAMESIZES, READWRITE, struct v4l2_frmsizeenum);
  _(VIDIOC_ENUM_FRAMEINTERVALS, READWRITE, struct v4l2_frmivalenum);
  /* Entries from file: sys/wdog.h */
  _(WDOGIOC_GMODE, READWRITE, struct wdog_mode);
  _(WDOGIOC_SMODE, WRITE, struct wdog_mode);
  _(WDOGIOC_WHICH, READ, struct wdog_mode);
  _(WDOGIOC_TICKLE, NONE);
  _(WDOGIOC_GTICKLER, READ, pid_t);
  _(WDOGIOC_GWDOGS, READWRITE, struct wdog_conf);
  /* Entries from file: soundcard.h */
  _(SNDCTL_DSP_RESET, NONE);
  _(SNDCTL_DSP_SYNC, NONE);
  _(SNDCTL_DSP_SPEED, READWRITE, sizeof(int));
  _(SOUND_PCM_READ_RATE, READ, sizeof(int));
  _(SNDCTL_DSP_STEREO, READWRITE, sizeof(int));
  _(SNDCTL_DSP_GETBLKSIZE, READWRITE, sizeof(int));
  _(SNDCTL_DSP_SETFMT, READWRITE, sizeof(int));
  _(SOUND_PCM_READ_BITS, READ, sizeof(int));
  _(SNDCTL_DSP_CHANNELS, READWRITE, sizeof(int));
  _(SOUND_PCM_READ_CHANNELS, READ, sizeof(int));
  _(SOUND_PCM_WRITE_FILTER, READWRITE, sizeof(int));
  _(SOUND_PCM_READ_FILTER, READ, sizeof(int));
  _(SNDCTL_DSP_POST, NONE);
  _(SNDCTL_DSP_SUBDIVIDE, READWRITE, sizeof(int));
  _(SNDCTL_DSP_SETFRAGMENT, READWRITE, sizeof(int));
  _(SNDCTL_DSP_GETFMTS, READ, sizeof(int));
  _(SNDCTL_DSP_GETOSPACE, READ, struct audio_buf_info);
  _(SNDCTL_DSP_GETISPACE, READ, struct audio_buf_info);
  _(SNDCTL_DSP_NONBLOCK, NONE);
  _(SNDCTL_DSP_GETCAPS, READ, sizeof(int));
  _(SNDCTL_DSP_GETTRIGGER, READ, sizeof(int));
  _(SNDCTL_DSP_SETTRIGGER, WRITE, sizeof(int));
  _(SNDCTL_DSP_GETIPTR, READ, struct count_info);
  _(SNDCTL_DSP_GETOPTR, READ, struct count_info);
  _(SNDCTL_DSP_MAPINBUF, READ, struct buffmem_desc);
  _(SNDCTL_DSP_MAPOUTBUF, READ, struct buffmem_desc);
  _(SNDCTL_DSP_SETSYNCRO, NONE);
  _(SNDCTL_DSP_SETDUPLEX, NONE);
  _(SNDCTL_DSP_PROFILE, WRITE, sizeof(int));
  _(SNDCTL_DSP_GETODELAY, READ, sizeof(int));
  _(SOUND_MIXER_INFO, READ, mixer_info);
  _(SOUND_OLD_MIXER_INFO, READ, _old_mixer_info);
  _(OSS_GETVERSION, READ, sizeof(int));
  _(SNDCTL_SYSINFO, READ, struct oss_sysinfo);
  _(SNDCTL_AUDIOINFO, READWRITE, struct oss_audioinfo);
  _(SNDCTL_ENGINEINFO, READWRITE, struct oss_audioinfo);
  _(SNDCTL_DSP_GETPLAYVOL, READ, uint);
  _(SNDCTL_DSP_SETPLAYVOL, WRITE, uint);
  _(SNDCTL_DSP_GETRECVOL, READ, uint);
  _(SNDCTL_DSP_SETRECVOL, WRITE, uint);
  _(SNDCTL_DSP_SKIP, NONE);
  _(SNDCTL_DSP_SILENCE, NONE);
  /* Entries from file: xen/xenio.h */
  _(EVTCHN_RESET, NONE);
  _(EVTCHN_BIND, WRITE, unsigned long);
  _(EVTCHN_UNBIND, WRITE, unsigned long);
#undef _
}

static bool ioctl_initialized = false;

struct ioctl_desc_compare {
  bool operator()(const ioctl_desc &left, const ioctl_desc &right) const {
    return left.req < right.req;
  }
};

static void ioctl_init() {
  ioctl_table_fill();
  InternalSort(&ioctl_table, ioctl_table_size, ioctl_desc_compare());

  bool bad = false;
  for (unsigned i = 0; i < ioctl_table_size - 1; ++i) {
    if (ioctl_table[i].req >= ioctl_table[i + 1].req) {
      Printf("Duplicate or unsorted ioctl request id %x >= %x (%s vs %s)\n",
             ioctl_table[i].req, ioctl_table[i + 1].req, ioctl_table[i].name,
             ioctl_table[i + 1].name);
      bad = true;
    }
  }

  if (bad)
    Die();

  ioctl_initialized = true;
}

static const ioctl_desc *ioctl_table_lookup(unsigned req) {
  int left = 0;
  int right = ioctl_table_size;
  while (left < right) {
    int mid = (left + right) / 2;
    if (ioctl_table[mid].req < req)
      left = mid + 1;
    else
      right = mid;
  }
  if (left == right && ioctl_table[left].req == req)
    return ioctl_table + left;
  else
    return nullptr;
}

static bool ioctl_decode(unsigned req, ioctl_desc *desc) {
  CHECK(desc);
  desc->req = req;
  desc->name = "<DECODED_IOCTL>";
  desc->size = IOC_SIZE(req);
  // Sanity check.
  if (desc->size > 0xFFFF)
    return false;
  unsigned dir = IOC_DIR(req);
  switch (dir) {
  case IOC_NONE:
    desc->type = ioctl_desc::NONE;
    break;
  case IOC_READ | IOC_WRITE:
    desc->type = ioctl_desc::READWRITE;
    break;
  case IOC_READ:
    desc->type = ioctl_desc::WRITE;
    break;
  case IOC_WRITE:
    desc->type = ioctl_desc::READ;
    break;
  default:
    return false;
  }
  // Size can be 0 iff type is NONE.
  if ((desc->type == IOC_NONE) != (desc->size == 0))
    return false;
  // Sanity check.
  if (IOC_TYPE(req) == 0)
    return false;
  return true;
}

static const ioctl_desc *ioctl_lookup(unsigned req) {
  const ioctl_desc *desc = ioctl_table_lookup(req);
  if (desc)
    return desc;

  // Try stripping access size from the request id.
  desc = ioctl_table_lookup(req & ~(IOC_SIZEMASK << IOC_SIZESHIFT));
  // Sanity check: requests that encode access size are either read or write and
  // have size of 0 in the table.
  if (desc && desc->size == 0 &&
      (desc->type == ioctl_desc::READWRITE || desc->type == ioctl_desc::WRITE ||
       desc->type == ioctl_desc::READ))
    return desc;
  return nullptr;
}

static void ioctl_common_pre(void *ctx, const ioctl_desc *desc, int d,
                             unsigned request, void *arg) {
  if (desc->type == ioctl_desc::READ || desc->type == ioctl_desc::READWRITE) {
    unsigned size = desc->size ? desc->size : IOC_SIZE(request);
    COMMON_INTERCEPTOR_READ_RANGE(ctx, arg, size);
  }
  if (desc->type != ioctl_desc::CUSTOM)
    return;
  if (request == IOCTL_SIOCGIFCONF) {
    struct __sanitizer_ifconf *ifc = (__sanitizer_ifconf *)arg;
    COMMON_INTERCEPTOR_READ_RANGE(ctx, (char *)&ifc->ifc_len,
                                  sizeof(ifc->ifc_len));
  }
}

static void ioctl_common_post(void *ctx, const ioctl_desc *desc, int res, int d,
                              unsigned request, void *arg) {
  if (desc->type == ioctl_desc::WRITE || desc->type == ioctl_desc::READWRITE) {
    // FIXME: add verbose output
    unsigned size = desc->size ? desc->size : IOC_SIZE(request);
    COMMON_INTERCEPTOR_WRITE_RANGE(ctx, arg, size);
  }
  if (desc->type != ioctl_desc::CUSTOM)
    return;
  if (request == IOCTL_SIOCGIFCONF) {
    struct __sanitizer_ifconf *ifc = (__sanitizer_ifconf *)arg;
    COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ifc->ifc_ifcu.ifcu_req, ifc->ifc_len);
  }
}
