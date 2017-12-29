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

#if SANITIZER_NETBSD

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

const unsigned ioctl_table_max = 1251;
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
  _(AFM_ADDFMAP, READWRITE, struct_atm_flowmap_sz);
  _(AFM_DELFMAP, READWRITE, struct_atm_flowmap_sz);
  _(AFM_CLEANFMAP, READWRITE, struct_atm_flowmap_sz);
  _(AFM_GETFMAP, READWRITE, struct_atm_flowmap_sz);
  /* Entries from file: altq/altq.h */
  _(ALTQGTYPE, READWRITE, struct_altqreq_sz);
  _(ALTQTBRSET, WRITE, struct_tbrreq_sz);
  _(ALTQTBRGET, READWRITE, struct_tbrreq_sz);
  /* Entries from file: altq/altq_blue.h */
  _(BLUE_IF_ATTACH, WRITE, struct_blue_interface_sz);
  _(BLUE_IF_DETACH, WRITE, struct_blue_interface_sz);
  _(BLUE_ENABLE, WRITE, struct_blue_interface_sz);
  _(BLUE_DISABLE, WRITE, struct_blue_interface_sz);
  _(BLUE_CONFIG, READWRITE, struct_blue_conf_sz);
  _(BLUE_GETSTATS, READWRITE, struct_blue_stats_sz);
  /* Entries from file: altq/altq_cbq.h */
  _(CBQ_IF_ATTACH, WRITE, struct_cbq_interface_sz);
  _(CBQ_IF_DETACH, WRITE, struct_cbq_interface_sz);
  _(CBQ_ENABLE, WRITE, struct_cbq_interface_sz);
  _(CBQ_DISABLE, WRITE, struct_cbq_interface_sz);
  _(CBQ_CLEAR_HIERARCHY, WRITE, struct_cbq_interface_sz);
  _(CBQ_ADD_CLASS, READWRITE, struct_cbq_add_class_sz);
  _(CBQ_DEL_CLASS, WRITE, struct_cbq_delete_class_sz);
  _(CBQ_MODIFY_CLASS, READWRITE, struct_cbq_modify_class_sz);
  _(CBQ_ADD_FILTER, READWRITE, struct_cbq_add_filter_sz);
  _(CBQ_DEL_FILTER, WRITE, struct_cbq_delete_filter_sz);
  _(CBQ_GETSTATS, READWRITE, struct_cbq_getstats_sz);
  /* Entries from file: altq/altq_cdnr.h */
  _(CDNR_IF_ATTACH, WRITE, struct_cdnr_interface_sz);
  _(CDNR_IF_DETACH, WRITE, struct_cdnr_interface_sz);
  _(CDNR_ENABLE, WRITE, struct_cdnr_interface_sz);
  _(CDNR_DISABLE, WRITE, struct_cdnr_interface_sz);
  _(CDNR_ADD_FILTER, READWRITE, struct_cdnr_add_filter_sz);
  _(CDNR_DEL_FILTER, WRITE, struct_cdnr_delete_filter_sz);
  _(CDNR_GETSTATS, READWRITE, struct_cdnr_get_stats_sz);
  _(CDNR_ADD_ELEM, READWRITE, struct_cdnr_add_element_sz);
  _(CDNR_DEL_ELEM, WRITE, struct_cdnr_delete_element_sz);
  _(CDNR_ADD_TBM, READWRITE, struct_cdnr_add_tbmeter_sz);
  _(CDNR_MOD_TBM, WRITE, struct_cdnr_modify_tbmeter_sz);
  _(CDNR_TBM_STATS, READWRITE, struct_cdnr_tbmeter_stats_sz);
  _(CDNR_ADD_TCM, READWRITE, struct_cdnr_add_trtcm_sz);
  _(CDNR_MOD_TCM, READWRITE, struct_cdnr_modify_trtcm_sz);
  _(CDNR_TCM_STATS, READWRITE, struct_cdnr_tcm_stats_sz);
  _(CDNR_ADD_TSW, READWRITE, struct_cdnr_add_tswtcm_sz);
  _(CDNR_MOD_TSW, READWRITE, struct_cdnr_modify_tswtcm_sz);
  /* Entries from file: altq/altq_fifoq.h */
  _(FIFOQ_IF_ATTACH, WRITE, struct_fifoq_interface_sz);
  _(FIFOQ_IF_DETACH, WRITE, struct_fifoq_interface_sz);
  _(FIFOQ_ENABLE, WRITE, struct_fifoq_interface_sz);
  _(FIFOQ_DISABLE, WRITE, struct_fifoq_interface_sz);
  _(FIFOQ_CONFIG, READWRITE, struct_fifoq_conf_sz);
  _(FIFOQ_GETSTATS, READWRITE, struct_fifoq_getstats_sz);
  /* Entries from file: altq/altq_hfsc.h */
  _(HFSC_IF_ATTACH, WRITE, struct_hfsc_attach_sz);
  _(HFSC_IF_DETACH, WRITE, struct_hfsc_interface_sz);
  _(HFSC_ENABLE, WRITE, struct_hfsc_interface_sz);
  _(HFSC_DISABLE, WRITE, struct_hfsc_interface_sz);
  _(HFSC_CLEAR_HIERARCHY, WRITE, struct_hfsc_interface_sz);
  _(HFSC_ADD_CLASS, READWRITE, struct_hfsc_add_class_sz);
  _(HFSC_DEL_CLASS, WRITE, struct_hfsc_delete_class_sz);
  _(HFSC_MOD_CLASS, WRITE, struct_hfsc_modify_class_sz);
  _(HFSC_ADD_FILTER, READWRITE, struct_hfsc_add_filter_sz);
  _(HFSC_DEL_FILTER, WRITE, struct_hfsc_delete_filter_sz);
  _(HFSC_GETSTATS, READWRITE, struct_hfsc_class_stats_sz);
  /* Entries from file: altq/altq_jobs.h */
  _(JOBS_IF_ATTACH, WRITE, struct_jobs_attach_sz);
  _(JOBS_IF_DETACH, WRITE, struct_jobs_interface_sz);
  _(JOBS_ENABLE, WRITE, struct_jobs_interface_sz);
  _(JOBS_DISABLE, WRITE, struct_jobs_interface_sz);
  _(JOBS_CLEAR, WRITE, struct_jobs_interface_sz);
  _(JOBS_ADD_CLASS, READWRITE, struct_jobs_add_class_sz);
  _(JOBS_DEL_CLASS, WRITE, struct_jobs_delete_class_sz);
  _(JOBS_MOD_CLASS, WRITE, struct_jobs_modify_class_sz);
  _(JOBS_ADD_FILTER, READWRITE, struct_jobs_add_filter_sz);
  _(JOBS_DEL_FILTER, WRITE, struct_jobs_delete_filter_sz);
  _(JOBS_GETSTATS, READWRITE, struct_jobs_class_stats_sz);
  /* Entries from file: altq/altq_priq.h */
  _(PRIQ_IF_ATTACH, WRITE, struct_priq_interface_sz);
  _(PRIQ_IF_DETACH, WRITE, struct_priq_interface_sz);
  _(PRIQ_ENABLE, WRITE, struct_priq_interface_sz);
  _(PRIQ_DISABLE, WRITE, struct_priq_interface_sz);
  _(PRIQ_CLEAR, WRITE, struct_priq_interface_sz);
  _(PRIQ_ADD_CLASS, READWRITE, struct_priq_add_class_sz);
  _(PRIQ_DEL_CLASS, WRITE, struct_priq_delete_class_sz);
  _(PRIQ_MOD_CLASS, WRITE, struct_priq_modify_class_sz);
  _(PRIQ_ADD_FILTER, READWRITE, struct_priq_add_filter_sz);
  _(PRIQ_DEL_FILTER, WRITE, struct_priq_delete_filter_sz);
  _(PRIQ_GETSTATS, READWRITE, struct_priq_class_stats_sz);
  /* Entries from file: altq/altq_red.h */
  _(RED_IF_ATTACH, WRITE, struct_red_interface_sz);
  _(RED_IF_DETACH, WRITE, struct_red_interface_sz);
  _(RED_ENABLE, WRITE, struct_red_interface_sz);
  _(RED_DISABLE, WRITE, struct_red_interface_sz);
  _(RED_CONFIG, READWRITE, struct_red_conf_sz);
  _(RED_GETSTATS, READWRITE, struct_red_stats_sz);
  _(RED_SETDEFAULTS, WRITE, struct_redparams_sz);
  /* Entries from file: altq/altq_rio.h */
  _(RIO_IF_ATTACH, WRITE, struct_rio_interface_sz);
  _(RIO_IF_DETACH, WRITE, struct_rio_interface_sz);
  _(RIO_ENABLE, WRITE, struct_rio_interface_sz);
  _(RIO_DISABLE, WRITE, struct_rio_interface_sz);
  _(RIO_CONFIG, READWRITE, struct_rio_conf_sz);
  _(RIO_GETSTATS, READWRITE, struct_rio_stats_sz);
  _(RIO_SETDEFAULTS, WRITE, struct_redparams_sz);
  /* Entries from file: altq/altq_wfq.h */
  _(WFQ_IF_ATTACH, WRITE, struct_wfq_interface_sz);
  _(WFQ_IF_DETACH, WRITE, struct_wfq_interface_sz);
  _(WFQ_ENABLE, WRITE, struct_wfq_interface_sz);
  _(WFQ_DISABLE, WRITE, struct_wfq_interface_sz);
  _(WFQ_CONFIG, READWRITE, struct_wfq_conf_sz);
  _(WFQ_GET_STATS, READWRITE, struct_wfq_getstats_sz);
  _(WFQ_GET_QID, READWRITE, struct_wfq_getqid_sz);
  _(WFQ_SET_WEIGHT, READWRITE, struct_wfq_setweight_sz);
  /* Entries from file: crypto/cryptodev.h */
  _(CRIOGET, READWRITE, sizeof(u32));
  _(CIOCFSESSION, WRITE, sizeof(u32));
  _(CIOCKEY, READWRITE, struct_crypt_kop_sz);
  _(CIOCNFKEYM, READWRITE, struct_crypt_mkop_sz);
  _(CIOCNFSESSION, WRITE, struct_crypt_sfop_sz);
  _(CIOCNCRYPTRETM, READWRITE, struct_cryptret_sz);
  _(CIOCNCRYPTRET, READWRITE, struct_crypt_result_sz);
  _(CIOCGSESSION, READWRITE, struct_session_op_sz);
  _(CIOCNGSESSION, READWRITE, struct_crypt_sgop_sz);
  _(CIOCCRYPT, READWRITE, struct_crypt_op_sz);
  _(CIOCNCRYPTM, READWRITE, struct_crypt_mop_sz);
  _(CIOCASYMFEAT, READ, sizeof(u32));
  /* Entries from file: dev/apm/apmio.h */
  _(APM_IOC_REJECT, WRITE, struct_apm_event_info_sz);
  _(APM_IOC_STANDBY, NONE, 0);
  _(APM_IOC_SUSPEND, NONE, 0);
  _(OAPM_IOC_GETPOWER, READ, struct_apm_power_info_sz);
  _(APM_IOC_GETPOWER, READWRITE, struct_apm_power_info_sz);
  _(APM_IOC_NEXTEVENT, READ, struct_apm_event_info_sz);
  _(APM_IOC_DEV_CTL, WRITE, struct_apm_ctl_sz);
  /* Entries from file: dev/dm/netbsd-dm.h */
  _(NETBSD_DM_IOCTL, READWRITE, struct_plistref_sz);
  /* Entries from file: dev/dmover/dmover_io.h */
  _(DMIO_SETFUNC, WRITE, struct_dmio_setfunc_sz);
  /* Entries from file: dev/dtv/dtvio_demux.h */
  _(DMX_START, NONE, 0);
  _(DMX_STOP, NONE, 0);
  _(DMX_SET_FILTER, WRITE, struct_dmx_sct_filter_params_sz);
  _(DMX_SET_PES_FILTER, WRITE, struct_dmx_pes_filter_params_sz);
  _(DMX_SET_BUFFER_SIZE, NONE, 0);
  _(DMX_GET_STC, READWRITE, struct_dmx_stc_sz);
  _(DMX_ADD_PID, WRITE, sizeof(u16));
  _(DMX_REMOVE_PID, WRITE, sizeof(u16));
  _(DMX_GET_CAPS, READ, struct_dmx_caps_sz);
  _(DMX_SET_SOURCE, WRITE, enum_dmx_source_sz);
  /* Entries from file: dev/dtv/dtvio_frontend.h */
  _(FE_READ_STATUS, READ, enum_fe_status_sz);
  _(FE_READ_BER, READ, sizeof(u32));
  _(FE_READ_SNR, READ, sizeof(u16));
  _(FE_READ_SIGNAL_STRENGTH, READ, sizeof(u16));
  _(FE_READ_UNCORRECTED_BLOCKS, READ, sizeof(u32));
  _(FE_SET_FRONTEND, READWRITE, struct_dvb_frontend_parameters_sz);
  _(FE_GET_FRONTEND, READ, struct_dvb_frontend_parameters_sz);
  _(FE_GET_EVENT, READ, struct_dvb_frontend_event_sz);
  _(FE_GET_INFO, READ, struct_dvb_frontend_info_sz);
  _(FE_DISEQC_RESET_OVERLOAD, NONE, 0);
  _(FE_DISEQC_SEND_MASTER_CMD, WRITE, struct_dvb_diseqc_master_cmd_sz);
  _(FE_DISEQC_RECV_SLAVE_REPLY, READ, struct_dvb_diseqc_slave_reply_sz);
  _(FE_DISEQC_SEND_BURST, WRITE, enum_fe_sec_mini_cmd_sz);
  _(FE_SET_TONE, WRITE, enum_fe_sec_tone_mode_sz);
  _(FE_SET_VOLTAGE, WRITE, enum_fe_sec_voltage_sz);
  _(FE_ENABLE_HIGH_LNB_VOLTAGE, WRITE, sizeof(int));
  _(FE_SET_FRONTEND_TUNE_MODE, WRITE, sizeof(unsigned int));
  _(FE_DISHNETWORK_SEND_LEGACY_CMD, WRITE, sizeof(unsigned long));
  /* Entries from file: dev/filemon/filemon.h */
  _(FILEMON_SET_FD, READWRITE, sizeof(int));
  _(FILEMON_SET_PID, READWRITE, sizeof(int));
  /* Entries from file: dev/hdaudio/hdaudioio.h */
  _(HDAUDIO_FGRP_INFO, READWRITE, struct_plistref_sz);
  _(HDAUDIO_FGRP_GETCONFIG, READWRITE, struct_plistref_sz);
  _(HDAUDIO_FGRP_SETCONFIG, READWRITE, struct_plistref_sz);
  _(HDAUDIO_FGRP_WIDGET_INFO, READWRITE, struct_plistref_sz);
  _(HDAUDIO_FGRP_CODEC_INFO, READWRITE, struct_plistref_sz);
  _(HDAUDIO_AFG_WIDGET_INFO, READWRITE, struct_plistref_sz);
  _(HDAUDIO_AFG_CODEC_INFO, READWRITE, struct_plistref_sz);
  /* Entries from file: dev/hdmicec/hdmicecio.h */
  _(CEC_GET_PHYS_ADDR, READ, sizeof(u16));
  _(CEC_GET_LOG_ADDRS, READ, sizeof(u16));
  _(CEC_SET_LOG_ADDRS, WRITE, sizeof(u16));
  _(CEC_GET_VENDOR_ID, READ, sizeof(u32));
  /* Entries from file: dev/hpc/hpcfbio.h */
  _(HPCFBIO_GCONF, READWRITE, struct_hpcfb_fbconf_sz);
  _(HPCFBIO_SCONF, WRITE, struct_hpcfb_fbconf_sz);
  _(HPCFBIO_GDSPCONF, READWRITE, struct_hpcfb_dspconf_sz);
  _(HPCFBIO_SDSPCONF, WRITE, struct_hpcfb_dspconf_sz);
  _(HPCFBIO_GOP, READ, struct_hpcfb_dsp_op_sz);
  _(HPCFBIO_SOP, READWRITE, struct_hpcfb_dsp_op_sz);
  /* Entries from file: dev/i2o/iopio.h */
  _(IOPIOCPT, READWRITE, struct_ioppt_sz);
  _(IOPIOCGLCT, READWRITE, struct_iovec_sz);
  _(IOPIOCGSTATUS, READWRITE, struct_iovec_sz);
  _(IOPIOCRECONFIG, NONE, 0);
  _(IOPIOCGTIDMAP, READWRITE, struct_iovec_sz);
  /* Entries from file: dev/ic/athioctl.h */
  _(SIOCGATHSTATS, READWRITE, struct_ifreq_sz);
  _(SIOCGATHDIAG, READWRITE, struct_ath_diag_sz);
  /* Entries from file: dev/ic/bt8xx.h */
  _(METEORCAPTUR, WRITE, sizeof(int));
  _(METEORCAPFRM, WRITE, struct_meteor_capframe_sz);
  _(METEORSETGEO, WRITE, struct_meteor_geomet_sz);
  _(METEORGETGEO, READ, struct_meteor_geomet_sz);
  _(METEORSTATUS, READ, sizeof(unsigned short));
  _(METEORSHUE, WRITE, sizeof(signed char));
  _(METEORGHUE, READ, sizeof(signed char));
  _(METEORSFMT, WRITE, sizeof(unsigned int));
  _(METEORGFMT, READ, sizeof(unsigned int));
  _(METEORSINPUT, WRITE, sizeof(unsigned int));
  _(METEORGINPUT, READ, sizeof(unsigned int));
  _(METEORSCHCV, WRITE, sizeof(unsigned char));
  _(METEORGCHCV, READ, sizeof(unsigned char));
  _(METEORSCOUNT, WRITE, struct_meteor_counts_sz);
  _(METEORGCOUNT, READ, struct_meteor_counts_sz);
  _(METEORSFPS, WRITE, sizeof(unsigned short));
  _(METEORGFPS, READ, sizeof(unsigned short));
  _(METEORSSIGNAL, WRITE, sizeof(unsigned int));
  _(METEORGSIGNAL, READ, sizeof(unsigned int));
  _(METEORSVIDEO, WRITE, struct_meteor_video_sz);
  _(METEORGVIDEO, READ, struct_meteor_video_sz);
  _(METEORSBRIG, WRITE, sizeof(unsigned char));
  _(METEORGBRIG, READ, sizeof(unsigned char));
  _(METEORSCSAT, WRITE, sizeof(unsigned char));
  _(METEORGCSAT, READ, sizeof(unsigned char));
  _(METEORSCONT, WRITE, sizeof(unsigned char));
  _(METEORGCONT, READ, sizeof(unsigned char));
  _(METEORSHWS, WRITE, sizeof(unsigned char));
  _(METEORGHWS, READ, sizeof(unsigned char));
  _(METEORSVWS, WRITE, sizeof(unsigned char));
  _(METEORGVWS, READ, sizeof(unsigned char));
  _(METEORSTS, WRITE, sizeof(unsigned char));
  _(METEORGTS, READ, sizeof(unsigned char));
  _(TVTUNER_SETCHNL, WRITE, sizeof(unsigned int));
  _(TVTUNER_GETCHNL, READ, sizeof(unsigned int));
  _(TVTUNER_SETTYPE, WRITE, sizeof(unsigned int));
  _(TVTUNER_GETTYPE, READ, sizeof(unsigned int));
  _(TVTUNER_GETSTATUS, READ, sizeof(unsigned int));
  _(TVTUNER_SETFREQ, WRITE, sizeof(unsigned int));
  _(TVTUNER_GETFREQ, READ, sizeof(unsigned int));
  _(TVTUNER_SETAFC, WRITE, sizeof(int));
  _(TVTUNER_GETAFC, READ, sizeof(int));
  _(RADIO_SETMODE, WRITE, sizeof(unsigned int));
  _(RADIO_GETMODE, READ, sizeof(unsigned char));
  _(RADIO_SETFREQ, WRITE, sizeof(unsigned int));
  _(RADIO_GETFREQ, READ, sizeof(unsigned int));
  _(METEORSACTPIXFMT, WRITE, sizeof(int));
  _(METEORGACTPIXFMT, READ, sizeof(int));
  _(METEORGSUPPIXFMT, READWRITE, struct_meteor_pixfmt_sz);
  _(TVTUNER_GETCHNLSET, READWRITE, struct_bktr_chnlset_sz);
  _(REMOTE_GETKEY, READ, struct_bktr_remote_sz);
  /* Entries from file: dev/ic/icp_ioctl.h */
  _(GDT_IOCTL_GENERAL, READWRITE, struct_gdt_ucmd_sz);
  _(GDT_IOCTL_DRVERS, READ, sizeof(int));
  _(GDT_IOCTL_CTRTYPE, READWRITE, struct_gdt_ctrt_sz);
  _(GDT_IOCTL_OSVERS, READ, struct_gdt_osv_sz);
  _(GDT_IOCTL_CTRCNT, READ, sizeof(int));
  _(GDT_IOCTL_EVENT, READWRITE, struct_gdt_event_sz);
  _(GDT_IOCTL_STATIST, READ, struct_gdt_statist_sz);
  _(GDT_IOCTL_RESCAN, READWRITE, struct_gdt_rescan_sz);
  /* Entries from file: dev/ic/isp_ioctl.h */
  _(ISP_SDBLEV, READWRITE, sizeof(int));
  _(ISP_RESETHBA, NONE, 0);
  _(ISP_RESCAN, NONE, 0);
  _(ISP_SETROLE, READWRITE, sizeof(int));
  _(ISP_GETROLE, READ, sizeof(int));
  _(ISP_GET_STATS, READ, struct_isp_stats_sz);
  _(ISP_CLR_STATS, NONE, 0);
  _(ISP_FC_LIP, NONE, 0);
  _(ISP_FC_GETDINFO, READWRITE, struct_isp_fc_device_sz);
  _(ISP_GET_FW_CRASH_DUMP, NONE, 0);
  _(ISP_FORCE_CRASH_DUMP, NONE, 0);
  _(ISP_FC_GETHINFO, READWRITE, struct_isp_hba_device_sz);
  _(ISP_TSK_MGMT, READWRITE, struct_isp_fc_tsk_mgmt_sz);
  _(ISP_FC_GETDLIST, NONE, 0);
  /* Entries from file: dev/ic/mlxio.h */
  _(MLXD_STATUS, READ, sizeof(int));
  _(MLXD_CHECKASYNC, READ, sizeof(int));
  _(MLXD_DETACH, WRITE, sizeof(int));
  _(MLX_RESCAN_DRIVES, NONE, 0);
  _(MLX_PAUSE_CHANNEL, WRITE, struct_mlx_pause_sz);
  _(MLX_COMMAND, READWRITE, struct_mlx_usercommand_sz);
  _(MLX_REBUILDASYNC, READWRITE, struct_mlx_rebuild_request_sz);
  _(MLX_REBUILDSTAT, READ, struct_mlx_rebuild_status_sz);
  _(MLX_GET_SYSDRIVE, READWRITE, sizeof(int));
  _(MLX_GET_CINFO, READ, struct_mlx_cinfo_sz);
  /* Entries from file: dev/ic/nvmeio.h */
  _(NVME_PASSTHROUGH_CMD, READWRITE, struct_nvme_pt_command_sz);
  /* Entries from file: dev/ir/irdaio.h */
  _(IRDA_RESET_PARAMS, NONE, 0);
  _(IRDA_SET_PARAMS, WRITE, struct_irda_params_sz);
  _(IRDA_GET_SPEEDMASK, READ, sizeof(unsigned int));
  _(IRDA_GET_TURNAROUNDMASK, READ, sizeof(unsigned int));
  _(IRFRAMETTY_GET_DEVICE, READ, sizeof(unsigned int));
  _(IRFRAMETTY_GET_DONGLE, READ, sizeof(unsigned int));
  _(IRFRAMETTY_SET_DONGLE, WRITE, sizeof(unsigned int));
  /* Entries from file: dev/isa/satlinkio.h */
  _(SATIORESET, NONE, 0);
  _(SATIOGID, READ, struct_satlink_id_sz);
  _(SATIOSBUFSIZE, WRITE, sizeof(int));
  /* Entries from file: dev/isa/isvio.h */
  _(ISV_CMD, READWRITE, struct_isv_cmd_sz);
  /* Entries from file: dev/isa/wtreg.h */
  _(WTQICMD, NONE, 0);
  /* Entries from file: dev/iscsi/iscsi_ioctl.h */
  _(ISCSI_GET_VERSION, READWRITE, struct_iscsi_get_version_parameters_sz);
  _(ISCSI_LOGIN, READWRITE, struct_iscsi_login_parameters_sz);
  _(ISCSI_LOGOUT, READWRITE, struct_iscsi_logout_parameters_sz);
  _(ISCSI_ADD_CONNECTION, READWRITE, struct_iscsi_login_parameters_sz);
  _(ISCSI_RESTORE_CONNECTION, READWRITE, struct_iscsi_login_parameters_sz);
  _(ISCSI_REMOVE_CONNECTION, READWRITE, struct_iscsi_remove_parameters_sz);
  _(ISCSI_CONNECTION_STATUS, READWRITE, struct_iscsi_conn_status_parameters_sz);
  _(ISCSI_SEND_TARGETS, READWRITE, struct_iscsi_send_targets_parameters_sz);
  _(ISCSI_SET_NODE_NAME, READWRITE, struct_iscsi_set_node_name_parameters_sz);
  _(ISCSI_IO_COMMAND, READWRITE, struct_iscsi_iocommand_parameters_sz);
  _(ISCSI_REGISTER_EVENT, READWRITE, struct_iscsi_register_event_parameters_sz);
  _(ISCSI_DEREGISTER_EVENT, READWRITE,
    struct_iscsi_register_event_parameters_sz);
  _(ISCSI_WAIT_EVENT, READWRITE, struct_iscsi_wait_event_parameters_sz);
  _(ISCSI_POLL_EVENT, READWRITE, struct_iscsi_wait_event_parameters_sz);
  /* Entries from file: dev/ofw/openfirmio.h */
  _(OFIOCGET, READWRITE, struct_ofiocdesc_sz);
  _(OFIOCSET, WRITE, struct_ofiocdesc_sz);
  _(OFIOCNEXTPROP, READWRITE, struct_ofiocdesc_sz);
  _(OFIOCGETOPTNODE, READ, sizeof(int));
  _(OFIOCGETNEXT, READWRITE, sizeof(int));
  _(OFIOCGETCHILD, READWRITE, sizeof(int));
  _(OFIOCFINDDEVICE, READWRITE, struct_ofiocdesc_sz);
  /* Entries from file: dev/pci/amrio.h */
  _(AMR_IO_VERSION, READ, sizeof(int));
  _(AMR_IO_COMMAND, READWRITE, struct_amr_user_ioctl_sz);
  /* Entries from file: dev/pci/mlyio.h */
  _(MLYIO_COMMAND, READWRITE, struct_mly_user_command_sz);
  _(MLYIO_HEALTH, WRITE, struct_mly_user_health_sz);
  /* Entries from file: dev/pci/pciio.h */
  _(PCI_IOC_CFGREAD, READWRITE, struct_pciio_cfgreg_sz);
  _(PCI_IOC_CFGWRITE, WRITE, struct_pciio_cfgreg_sz);
  _(PCI_IOC_BDF_CFGREAD, READWRITE, struct_pciio_bdf_cfgreg_sz);
  _(PCI_IOC_BDF_CFGWRITE, WRITE, struct_pciio_bdf_cfgreg_sz);
  _(PCI_IOC_BUSINFO, READ, struct_pciio_businfo_sz);
  _(PCI_IOC_DRVNAME, READWRITE, struct_pciio_drvname_sz);
  _(PCI_IOC_DRVNAMEONBUS, READWRITE, struct_pciio_drvnameonbus_sz);
  /* Entries from file: dev/pci/tweio.h */
  _(TWEIO_COMMAND, READWRITE, struct_twe_usercommand_sz);
  _(TWEIO_STATS, READWRITE, union_twe_statrequest_sz);
  _(TWEIO_AEN_POLL, READ, sizeof(int));
  _(TWEIO_AEN_WAIT, READ, sizeof(int));
  _(TWEIO_SET_PARAM, WRITE, struct_twe_paramcommand_sz);
  _(TWEIO_GET_PARAM, WRITE, struct_twe_paramcommand_sz);
  _(TWEIO_RESET, NONE, 0);
  _(TWEIO_ADD_UNIT, WRITE, struct_twe_drivecommand_sz);
  _(TWEIO_DEL_UNIT, WRITE, struct_twe_drivecommand_sz);
  /* Entries from file: dev/pcmcia/if_cnwioctl.h */
  _(SIOCSCNWDOMAIN, WRITE, struct_ifreq_sz);
  _(SIOCGCNWDOMAIN, READWRITE, struct_ifreq_sz);
  _(SIOCSCNWKEY, READWRITE, struct_ifreq_sz);
  _(SIOCGCNWSTATUS, READWRITE, struct_cnwstatus_sz);
  _(SIOCGCNWSTATS, READWRITE, struct_cnwistats_sz);
  _(SIOCGCNWTRAIL, READWRITE, struct_cnwitrail_sz);
  /* Entries from file: dev/pcmcia/if_rayreg.h */
  _(SIOCGRAYSIGLEV, READWRITE, struct_ifreq_sz);
  /* Entries from file: dev/raidframe/raidframeio.h */
  _(RAIDFRAME_SHUTDOWN, NONE, 0);
  _(RAIDFRAME_TUR, WRITE, sizeof(u64));
  _(RAIDFRAME_FAIL_DISK, WRITE, struct_rf_recon_req_sz);
  _(RAIDFRAME_CHECK_RECON_STATUS, READWRITE, sizeof(int));
  _(RAIDFRAME_REWRITEPARITY, NONE, 0);
  _(RAIDFRAME_COPYBACK, NONE, 0);
  _(RAIDFRAME_SPARET_WAIT, READ, struct_RF_SparetWait_sz);
  _(RAIDFRAME_SEND_SPARET, WRITE, sizeof(uptr));
  _(RAIDFRAME_ABORT_SPARET_WAIT, NONE, 0);
  _(RAIDFRAME_START_ATRACE, NONE, 0);
  _(RAIDFRAME_STOP_ATRACE, NONE, 0);
  _(RAIDFRAME_GET_SIZE, READ, sizeof(int));
  _(RAIDFRAME_RESET_ACCTOTALS, NONE, 0);
  _(RAIDFRAME_KEEP_ACCTOTALS, WRITE, sizeof(int));
  _(RAIDFRAME_GET_COMPONENT_LABEL, READWRITE, sizeof(uptr));
  _(RAIDFRAME_SET_COMPONENT_LABEL, WRITE, struct_RF_ComponentLabel_sz);
  _(RAIDFRAME_INIT_LABELS, WRITE, struct_RF_ComponentLabel_sz);
  _(RAIDFRAME_ADD_HOT_SPARE, WRITE, struct_RF_SingleComponent_sz);
  _(RAIDFRAME_REMOVE_HOT_SPARE, WRITE, struct_RF_SingleComponent_sz);
  _(RAIDFRAME_REBUILD_IN_PLACE, WRITE, struct_RF_SingleComponent_sz);
  _(RAIDFRAME_CHECK_PARITY, READWRITE, sizeof(int));
  _(RAIDFRAME_CHECK_PARITYREWRITE_STATUS, READWRITE, sizeof(int));
  _(RAIDFRAME_CHECK_COPYBACK_STATUS, READWRITE, sizeof(int));
  _(RAIDFRAME_SET_AUTOCONFIG, READWRITE, sizeof(int));
  _(RAIDFRAME_SET_ROOT, READWRITE, sizeof(int));
  _(RAIDFRAME_DELETE_COMPONENT, WRITE, struct_RF_SingleComponent_sz);
  _(RAIDFRAME_INCORPORATE_HOT_SPARE, WRITE, struct_RF_SingleComponent_sz);
  _(RAIDFRAME_CHECK_RECON_STATUS_EXT, READWRITE, sizeof(uptr));
  _(RAIDFRAME_CHECK_PARITYREWRITE_STATUS_EXT, READWRITE, sizeof(uptr));
  _(RAIDFRAME_CHECK_COPYBACK_STATUS_EXT, READWRITE, sizeof(uptr));
  _(RAIDFRAME_CONFIGURE, WRITE, sizeof(uptr));
  _(RAIDFRAME_GET_INFO, READWRITE, sizeof(uptr));
  _(RAIDFRAME_PARITYMAP_STATUS, READ, struct_rf_pmstat_sz);
  _(RAIDFRAME_PARITYMAP_GET_DISABLE, READ, sizeof(int));
  _(RAIDFRAME_PARITYMAP_SET_DISABLE, WRITE, sizeof(int));
  _(RAIDFRAME_PARITYMAP_SET_PARAMS, WRITE, struct_rf_pmparams_sz);
  _(RAIDFRAME_SET_LAST_UNIT, WRITE, sizeof(int));
  /* Entries from file: dev/sbus/mbppio.h */
  _(MBPPIOCSPARAM, WRITE, struct_mbpp_param_sz);
  _(MBPPIOCGPARAM, READ, struct_mbpp_param_sz);
  _(MBPPIOCGSTAT, READ, sizeof(int));
  /* Entries from file: dev/scsipi/ses.h */
  _(SESIOC_GETNOBJ, NONE, 0);
  _(SESIOC_GETOBJMAP, NONE, 0);
  _(SESIOC_GETENCSTAT, NONE, 0);
  _(SESIOC_SETENCSTAT, NONE, 0);
  _(SESIOC_GETOBJSTAT, NONE, 0);
  _(SESIOC_SETOBJSTAT, NONE, 0);
  _(SESIOC_GETTEXT, NONE, 0);
  _(SESIOC_INIT, NONE, 0);
  /* Entries from file: dev/sun/disklabel.h */
  _(SUN_DKIOCGGEOM, READ, struct_sun_dkgeom_sz);
  _(SUN_DKIOCINFO, READ, struct_sun_dkctlr_sz);
  _(SUN_DKIOCGPART, READ, struct_sun_dkpart_sz);
  /* Entries from file: dev/sun/fbio.h */
  _(FBIOGTYPE, READ, struct_fbtype_sz);
  _(FBIOPUTCMAP, WRITE, struct_fbcmap_sz);
  _(FBIOGETCMAP, WRITE, struct_fbcmap_sz);
  _(FBIOGATTR, READ, struct_fbgattr_sz);
  _(FBIOSVIDEO, WRITE, sizeof(int));
  _(FBIOGVIDEO, READ, sizeof(int));
  _(FBIOSCURSOR, WRITE, struct_fbcursor_sz);
  _(FBIOGCURSOR, READWRITE, struct_fbcursor_sz);
  _(FBIOSCURPOS, WRITE, struct_fbcurpos_sz);
  _(FBIOGCURPOS, WRITE, struct_fbcurpos_sz);
  _(FBIOGCURMAX, READ, struct_fbcurpos_sz);
  /* Entries from file: dev/sun/kbio.h */
  _(KIOCTRANS, WRITE, sizeof(int));
  _(KIOCSETKEY, READWRITE, struct_okiockey_sz);
  _(KIOCGETKEY, READWRITE, struct_okiockey_sz);
  _(KIOCGTRANS, READ, sizeof(int));
  _(KIOCCMD, WRITE, sizeof(int));
  _(KIOCTYPE, READ, sizeof(int));
  _(KIOCSDIRECT, WRITE, sizeof(int));
  _(KIOCSKEY, WRITE, struct_kiockeymap_sz);
  _(KIOCGKEY, READWRITE, struct_kiockeymap_sz);
  _(KIOCSLED, WRITE, sizeof(char));
  _(KIOCGLED, READ, sizeof(char));
  _(KIOCLAYOUT, READ, sizeof(int));
  /* Entries from file: dev/sun/vuid_event.h */
  _(VUIDSFORMAT, WRITE, sizeof(int));
  _(VUIDGFORMAT, READ, sizeof(int));
  /* Entries from file: dev/tc/sticio.h */
  _(STICIO_GXINFO, READ, struct_stic_xinfo_sz);
  _(STICIO_RESET, NONE, 0);
  _(STICIO_STARTQ, NONE, 0);
  _(STICIO_STOPQ, NONE, 0);
  /* Entries from file: dev/usb/ukyopon.h */
  _(UKYOPON_IDENTIFY, READ, struct_ukyopon_identify_sz);
  /* Entries from file: dev/usb/urio.h */
  _(URIO_SEND_COMMAND, READWRITE, struct_urio_command_sz);
  _(URIO_RECV_COMMAND, READWRITE, struct_urio_command_sz);
  /* Entries from file: dev/usb/usb.h */
  _(USB_REQUEST, READWRITE, struct_usb_ctl_request_sz);
  _(USB_SETDEBUG, WRITE, sizeof(int));
  _(USB_DISCOVER, NONE, 0);
  _(USB_DEVICEINFO, READWRITE, struct_usb_device_info_sz);
  _(USB_DEVICEINFO_OLD, READWRITE, struct_usb_device_info_old_sz);
  _(USB_DEVICESTATS, READ, struct_usb_device_stats_sz);
  _(USB_GET_REPORT_DESC, READ, struct_usb_ctl_report_desc_sz);
  _(USB_SET_IMMED, WRITE, sizeof(int));
  _(USB_GET_REPORT, READWRITE, struct_usb_ctl_report_sz);
  _(USB_SET_REPORT, WRITE, struct_usb_ctl_report_sz);
  _(USB_GET_REPORT_ID, READ, sizeof(int));
  _(USB_GET_CONFIG, READ, sizeof(int));
  _(USB_SET_CONFIG, WRITE, sizeof(int));
  _(USB_GET_ALTINTERFACE, READWRITE, struct_usb_alt_interface_sz);
  _(USB_SET_ALTINTERFACE, READWRITE, struct_usb_alt_interface_sz);
  _(USB_GET_NO_ALT, READWRITE, struct_usb_alt_interface_sz);
  _(USB_GET_DEVICE_DESC, READ, struct_usb_device_descriptor_sz);
  _(USB_GET_CONFIG_DESC, READWRITE, struct_usb_config_desc_sz);
  _(USB_GET_INTERFACE_DESC, READWRITE, struct_usb_interface_desc_sz);
  _(USB_GET_ENDPOINT_DESC, READWRITE, struct_usb_endpoint_desc_sz);
  _(USB_GET_FULL_DESC, READWRITE, struct_usb_full_desc_sz);
  _(USB_GET_STRING_DESC, READWRITE, struct_usb_string_desc_sz);
  _(USB_DO_REQUEST, READWRITE, struct_usb_ctl_request_sz);
  _(USB_GET_DEVICEINFO, READ, struct_usb_device_info_sz);
  _(USB_GET_DEVICEINFO_OLD, READ, struct_usb_device_info_old_sz);
  _(USB_SET_SHORT_XFER, WRITE, sizeof(int));
  _(USB_SET_TIMEOUT, WRITE, sizeof(int));
  _(USB_SET_BULK_RA, WRITE, sizeof(int));
  _(USB_SET_BULK_WB, WRITE, sizeof(int));
  _(USB_SET_BULK_RA_OPT, WRITE, struct_usb_bulk_ra_wb_opt_sz);
  _(USB_SET_BULK_WB_OPT, WRITE, struct_usb_bulk_ra_wb_opt_sz);
  _(USB_GET_CM_OVER_DATA, READ, sizeof(int));
  _(USB_SET_CM_OVER_DATA, WRITE, sizeof(int));
  /* Entries from file: dev/usb/utoppy.h */
  _(UTOPPYIOTURBO, WRITE, sizeof(int));
  _(UTOPPYIOCANCEL, NONE, 0);
  _(UTOPPYIOREBOOT, NONE, 0);
  _(UTOPPYIOSTATS, READ, struct_utoppy_stats_sz);
  _(UTOPPYIORENAME, WRITE, struct_utoppy_rename_sz);
  _(UTOPPYIOMKDIR, WRITE, sizeof(uptr));
  _(UTOPPYIODELETE, WRITE, sizeof(uptr));
  _(UTOPPYIOREADDIR, WRITE, sizeof(uptr));
  _(UTOPPYIOREADFILE, WRITE, struct_utoppy_readfile_sz);
  _(UTOPPYIOWRITEFILE, WRITE, struct_utoppy_writefile_sz);
  /* Entries from file: dev/vme/xio.h */
  _(DIOSXDCMD, READWRITE, struct_xd_iocmd_sz);
  /* Entries from file: dev/wscons/wsdisplay_usl_io.h */
  _(VT_OPENQRY, READ, sizeof(int));
  _(VT_SETMODE, WRITE, struct_vt_mode_sz);
  _(VT_GETMODE, READ, struct_vt_mode_sz);
  _(VT_RELDISP, NONE, 0);
  _(VT_ACTIVATE, NONE, 0);
  _(VT_WAITACTIVE, NONE, 0);
  _(VT_GETACTIVE, READ, sizeof(int));
  _(VT_GETSTATE, READ, struct_vt_stat_sz);
  _(KDGETKBENT, READWRITE, struct_kbentry_sz);
  _(KDGKBMODE, READ, sizeof(int));
  _(KDSKBMODE, NONE, 0);
  _(KDMKTONE, NONE, 0);
  _(KDSETMODE, NONE, 0);
  _(KDENABIO, NONE, 0);
  _(KDDISABIO, NONE, 0);
  _(KDGKBTYPE, READ, sizeof(char));
  _(KDGETLED, READ, sizeof(int));
  _(KDSETLED, NONE, 0);
  _(KDSETRAD, NONE, 0);
  _(VGAPCVTID, READWRITE, struct_pcvtid_sz);
  _(CONS_GETVERS, READ, sizeof(int));
  /* Entries from file: dev/wscons/wsconsio.h */
  _(WSKBDIO_GTYPE, READ, sizeof(unsigned int));
  _(WSKBDIO_BELL, NONE, 0);
  _(WSKBDIO_COMPLEXBELL, WRITE, struct_wskbd_bell_data_sz);
  _(WSKBDIO_SETBELL, WRITE, struct_wskbd_bell_data_sz);
  _(WSKBDIO_GETBELL, READ, struct_wskbd_bell_data_sz);
  _(WSKBDIO_SETDEFAULTBELL, WRITE, struct_wskbd_bell_data_sz);
  _(WSKBDIO_GETDEFAULTBELL, READ, struct_wskbd_bell_data_sz);
  _(WSKBDIO_SETKEYREPEAT, WRITE, struct_wskbd_keyrepeat_data_sz);
  _(WSKBDIO_GETKEYREPEAT, READ, struct_wskbd_keyrepeat_data_sz);
  _(WSKBDIO_SETDEFAULTKEYREPEAT, WRITE, struct_wskbd_keyrepeat_data_sz);
  _(WSKBDIO_GETDEFAULTKEYREPEAT, READ, struct_wskbd_keyrepeat_data_sz);
  _(WSKBDIO_SETLEDS, WRITE, sizeof(int));
  _(WSKBDIO_GETLEDS, READ, sizeof(int));
  _(WSKBDIO_GETMAP, READWRITE, struct_wskbd_map_data_sz);
  _(WSKBDIO_SETMAP, WRITE, struct_wskbd_map_data_sz);
  _(WSKBDIO_GETENCODING, READ, sizeof(int));
  _(WSKBDIO_SETENCODING, WRITE, sizeof(int));
  _(WSKBDIO_SETMODE, WRITE, sizeof(int));
  _(WSKBDIO_GETMODE, READ, sizeof(int));
  _(WSKBDIO_SETKEYCLICK, WRITE, sizeof(int));
  _(WSKBDIO_GETKEYCLICK, READ, sizeof(int));
  _(WSKBDIO_GETSCROLL, READ, struct_wskbd_scroll_data_sz);
  _(WSKBDIO_SETSCROLL, WRITE, struct_wskbd_scroll_data_sz);
  _(WSKBDIO_SETVERSION, WRITE, sizeof(int));
  _(WSMOUSEIO_GTYPE, READ, sizeof(unsigned int));
  _(WSMOUSEIO_SRES, WRITE, sizeof(unsigned int));
  _(WSMOUSEIO_SSCALE, WRITE, sizeof(unsigned int));
  _(WSMOUSEIO_SRATE, WRITE, sizeof(unsigned int));
  _(WSMOUSEIO_SCALIBCOORDS, WRITE, struct_wsmouse_calibcoords_sz);
  _(WSMOUSEIO_GCALIBCOORDS, READ, struct_wsmouse_calibcoords_sz);
  _(WSMOUSEIO_GETID, READWRITE, struct_wsmouse_id_sz);
  _(WSMOUSEIO_GETREPEAT, READ, struct_wsmouse_repeat_sz);
  _(WSMOUSEIO_SETREPEAT, WRITE, struct_wsmouse_repeat_sz);
  _(WSMOUSEIO_SETVERSION, WRITE, sizeof(int));
  _(WSDISPLAYIO_GTYPE, READ, sizeof(unsigned int));
  _(WSDISPLAYIO_GINFO, READ, struct_wsdisplay_fbinfo_sz);
  _(WSDISPLAYIO_GETCMAP, WRITE, struct_wsdisplay_cmap_sz);
  _(WSDISPLAYIO_PUTCMAP, WRITE, struct_wsdisplay_cmap_sz);
  _(WSDISPLAYIO_GVIDEO, READ, sizeof(unsigned int));
  _(WSDISPLAYIO_SVIDEO, WRITE, sizeof(unsigned int));
  _(WSDISPLAYIO_GCURPOS, READ, struct_wsdisplay_curpos_sz);
  _(WSDISPLAYIO_SCURPOS, WRITE, struct_wsdisplay_curpos_sz);
  _(WSDISPLAYIO_GCURMAX, READ, struct_wsdisplay_curpos_sz);
  _(WSDISPLAYIO_GCURSOR, READWRITE, struct_wsdisplay_cursor_sz);
  _(WSDISPLAYIO_SCURSOR, WRITE, struct_wsdisplay_cursor_sz);
  _(WSDISPLAYIO_GMODE, READ, sizeof(unsigned int));
  _(WSDISPLAYIO_SMODE, WRITE, sizeof(unsigned int));
  _(WSDISPLAYIO_LDFONT, WRITE, struct_wsdisplay_font_sz);
  _(WSDISPLAYIO_ADDSCREEN, WRITE, struct_wsdisplay_addscreendata_sz);
  _(WSDISPLAYIO_DELSCREEN, WRITE, struct_wsdisplay_delscreendata_sz);
  _(WSDISPLAYIO_SFONT, WRITE, struct_wsdisplay_usefontdata_sz);
  _(_O_WSDISPLAYIO_SETKEYBOARD, READWRITE, struct_wsdisplay_kbddata_sz);
  _(WSDISPLAYIO_GETPARAM, READWRITE, struct_wsdisplay_param_sz);
  _(WSDISPLAYIO_SETPARAM, READWRITE, struct_wsdisplay_param_sz);
  _(WSDISPLAYIO_GETACTIVESCREEN, READ, sizeof(int));
  _(WSDISPLAYIO_GETWSCHAR, READWRITE, struct_wsdisplay_char_sz);
  _(WSDISPLAYIO_PUTWSCHAR, READWRITE, struct_wsdisplay_char_sz);
  _(WSDISPLAYIO_DGSCROLL, READ, struct_wsdisplay_scroll_data_sz);
  _(WSDISPLAYIO_DSSCROLL, WRITE, struct_wsdisplay_scroll_data_sz);
  _(WSDISPLAYIO_GMSGATTRS, READ, struct_wsdisplay_msgattrs_sz);
  _(WSDISPLAYIO_SMSGATTRS, WRITE, struct_wsdisplay_msgattrs_sz);
  _(WSDISPLAYIO_GBORDER, READ, sizeof(int));
  _(WSDISPLAYIO_SBORDER, WRITE, sizeof(int));
  _(WSDISPLAYIO_SSPLASH, WRITE, sizeof(int));
  _(WSDISPLAYIO_SPROGRESS, WRITE, sizeof(int));
  _(WSDISPLAYIO_LINEBYTES, READ, sizeof(unsigned int));
  _(WSDISPLAYIO_SETVERSION, WRITE, sizeof(int));
  _(WSMUXIO_ADD_DEVICE, WRITE, struct_wsmux_device_sz);
  _(WSMUXIO_REMOVE_DEVICE, WRITE, struct_wsmux_device_sz);
  _(WSMUXIO_LIST_DEVICES, READWRITE, struct_wsmux_device_list_sz);
  _(WSMUXIO_INJECTEVENT, WRITE, struct_wscons_event_sz);
  _(WSDISPLAYIO_GET_BUSID, READ, struct_wsdisplayio_bus_id_sz);
  _(WSDISPLAYIO_GET_EDID, READWRITE, struct_wsdisplayio_edid_info_sz);
  _(WSDISPLAYIO_SET_POLLING, WRITE, sizeof(int));
  _(WSDISPLAYIO_GET_FBINFO, READWRITE, struct_wsdisplayio_fbinfo_sz);
  _(WSDISPLAYIO_DOBLIT, READWRITE, struct_wsdisplayio_blit_sz);
  _(WSDISPLAYIO_WAITBLIT, READWRITE, struct_wsdisplayio_blit_sz);
  /* Entries from file: dev/biovar.h */
  _(BIOCLOCATE, READWRITE, struct_bio_locate_sz);
  _(BIOCINQ, READWRITE, struct_bioc_inq_sz);
  _(BIOCDISK_NOVOL, READWRITE, struct_bioc_disk_sz);
  _(BIOCDISK, READWRITE, struct_bioc_disk_sz);
  _(BIOCVOL, READWRITE, struct_bioc_vol_sz);
  _(BIOCALARM, READWRITE, struct_bioc_alarm_sz);
  _(BIOCBLINK, READWRITE, struct_bioc_blink_sz);
  _(BIOCSETSTATE, READWRITE, struct_bioc_setstate_sz);
  _(BIOCVOLOPS, READWRITE, struct_bioc_volops_sz);
  /* Entries from file: dev/md.h */
  _(MD_GETCONF, READ, struct_md_conf_sz);
  _(MD_SETCONF, WRITE, struct_md_conf_sz);
  /* Entries from file: dev/ccdvar.h */
  _(CCDIOCSET, READWRITE, struct_ccd_ioctl_sz);
  _(CCDIOCCLR, WRITE, struct_ccd_ioctl_sz);
  /* Entries from file: dev/cgdvar.h */
  _(CGDIOCSET, READWRITE, struct_cgd_ioctl_sz);
  _(CGDIOCCLR, WRITE, struct_cgd_ioctl_sz);
  _(CGDIOCGET, READWRITE, struct_cgd_user_sz);
  /* Entries from file: dev/fssvar.h */
  _(FSSIOCSET, WRITE, struct_fss_set_sz);
  _(FSSIOCGET, READ, struct_fss_get_sz);
  _(FSSIOCCLR, NONE, 0);
  _(FSSIOFSET, WRITE, sizeof(int));
  _(FSSIOFGET, READ, sizeof(int));
  /* Entries from file: dev/bluetooth/btdev.h */
  _(BTDEV_ATTACH, WRITE, struct_plistref_sz);
  _(BTDEV_DETACH, WRITE, struct_plistref_sz);
  /* Entries from file: dev/bluetooth/btsco.h */
  _(BTSCO_GETINFO, READ, struct_btsco_info_sz);
  /* Entries from file: dev/kttcpio.h */
  _(KTTCP_IO_SEND, READWRITE, struct_kttcp_io_args_sz);
  _(KTTCP_IO_RECV, READWRITE, struct_kttcp_io_args_sz);
  /* Entries from file: dev/lockstat.h */
  _(IOC_LOCKSTAT_GVERSION, READ, sizeof(int));
  _(IOC_LOCKSTAT_ENABLE, WRITE, struct_lsenable_sz);
  _(IOC_LOCKSTAT_DISABLE, READ, struct_lsdisable_sz);
  /* Entries from file: dev/vndvar.h */
  _(VNDIOCSET, READWRITE, struct_vnd_ioctl_sz);
  _(VNDIOCCLR, WRITE, struct_vnd_ioctl_sz);
  _(VNDIOCGET, READWRITE, struct_vnd_user_sz);
  /* Entries from file: dev/spkrio.h */
  _(SPKRTONE, WRITE, struct_tone_sz);
  _(SPKRTUNE, NONE, 0);
  _(SPKRGETVOL, READ, sizeof(unsigned int));
  _(SPKRSETVOL, WRITE, sizeof(unsigned int));
  /* Entries from file: net/bpf.h */
  _(BIOCGBLEN, READ, sizeof(unsigned int));
  _(BIOCSBLEN, READWRITE, sizeof(unsigned int));
  _(BIOCSETF, WRITE, struct_bpf_program_sz);
  _(BIOCFLUSH, NONE, 0);
  _(BIOCPROMISC, NONE, 0);
  _(BIOCGDLT, READ, sizeof(unsigned int));
  _(BIOCGETIF, READ, struct_ifreq_sz);
  _(BIOCSETIF, WRITE, struct_ifreq_sz);
  _(BIOCGSTATS, READ, struct_bpf_stat_sz);
  _(BIOCGSTATSOLD, READ, struct_bpf_stat_old_sz);
  _(BIOCIMMEDIATE, WRITE, sizeof(unsigned int));
  _(BIOCVERSION, READ, struct_bpf_version_sz);
  _(BIOCSTCPF, WRITE, struct_bpf_program_sz);
  _(BIOCSUDPF, WRITE, struct_bpf_program_sz);
  _(BIOCGHDRCMPLT, READ, sizeof(unsigned int));
  _(BIOCSHDRCMPLT, WRITE, sizeof(unsigned int));
  _(BIOCSDLT, WRITE, sizeof(unsigned int));
  _(BIOCGDLTLIST, READWRITE, struct_bpf_dltlist_sz);
  _(BIOCGSEESENT, READ, sizeof(unsigned int));
  _(BIOCSSEESENT, WRITE, sizeof(unsigned int));
  _(BIOCSRTIMEOUT, WRITE, struct_timeval_sz);
  _(BIOCGRTIMEOUT, READ, struct_timeval_sz);
  _(BIOCGFEEDBACK, READ, sizeof(unsigned int));
  _(BIOCSFEEDBACK, WRITE, sizeof(unsigned int));
  /* Entries from file: net/if_atm.h */
  _(SIOCRAWATM, READWRITE, sizeof(int));
  _(SIOCATMENA, READWRITE, struct_atm_pseudoioctl_sz);
  _(SIOCATMDIS, READWRITE, struct_atm_pseudoioctl_sz);
  _(SIOCSPVCTX, READWRITE, struct_pvctxreq_sz);
  _(SIOCGPVCTX, READWRITE, struct_pvctxreq_sz);
  _(SIOCSPVCSIF, READWRITE, struct_ifreq_sz);
  _(SIOCGPVCSIF, READWRITE, struct_ifreq_sz);
  /* Entries from file: net/if_gre.h */
  _(GRESADDRS, WRITE, struct_ifreq_sz);
  _(GRESADDRD, WRITE, struct_ifreq_sz);
  _(GREGADDRS, READWRITE, struct_ifreq_sz);
  _(GREGADDRD, READWRITE, struct_ifreq_sz);
  _(GRESPROTO, WRITE, struct_ifreq_sz);
  _(GREGPROTO, READWRITE, struct_ifreq_sz);
  _(GRESSOCK, WRITE, struct_ifreq_sz);
  _(GREDSOCK, WRITE, struct_ifreq_sz);
  /* Entries from file: net/if_ppp.h */
  _(PPPIOCGRAWIN, READ, struct_ppp_rawin_sz);
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
  _(PPPIOCGXASYNCMAP, READ, (8 * sizeof(u32)));
  _(PPPIOCSXASYNCMAP, WRITE, (8 * sizeof(u32)));
  _(PPPIOCXFERUNIT, NONE, 0);
  _(PPPIOCSCOMPRESS, WRITE, struct_ppp_option_data_sz);
  _(PPPIOCGNPMODE, READWRITE, struct_npioctl_sz);
  _(PPPIOCSNPMODE, WRITE, struct_npioctl_sz);
  _(PPPIOCGIDLE, READ, struct_ppp_idle_sz);
  _(PPPIOCGMTU, READ, sizeof(int));
  _(PPPIOCSMTU, WRITE, sizeof(int));
  _(SIOCGPPPSTATS, READWRITE, struct_ifpppstatsreq_sz);
  _(SIOCGPPPCSTATS, READWRITE, struct_ifpppcstatsreq_sz);
  /* Entries from file: net/npf.h */
  _(IOC_NPF_VERSION, READ, sizeof(int));
  _(IOC_NPF_SWITCH, WRITE, sizeof(int));
  _(IOC_NPF_LOAD, READWRITE, struct_plistref_sz);
  _(IOC_NPF_TABLE, WRITE, struct_npf_ioctl_table_sz);
  _(IOC_NPF_STATS, WRITE, sizeof(uptr));
  _(IOC_NPF_SAVE, READ, struct_plistref_sz);
  _(IOC_NPF_RULE, READWRITE, struct_plistref_sz);
  _(IOC_NPF_CONN_LOOKUP, READWRITE, struct_plistref_sz);
  /* Entries from file: net/if_pppoe.h */
  _(PPPOESETPARMS, WRITE, struct_pppoediscparms_sz);
  _(PPPOEGETPARMS, READWRITE, struct_pppoediscparms_sz);
  _(PPPOEGETSESSION, READWRITE, struct_pppoeconnectionstate_sz);
  /* Entries from file: net/if_sppp.h */
  _(SPPPGETAUTHCFG, READWRITE, struct_spppauthcfg_sz);
  _(SPPPSETAUTHCFG, WRITE, struct_spppauthcfg_sz);
  _(SPPPGETLCPCFG, READWRITE, struct_sppplcpcfg_sz);
  _(SPPPSETLCPCFG, WRITE, struct_sppplcpcfg_sz);
  _(SPPPGETSTATUS, READWRITE, struct_spppstatus_sz);
  _(SPPPGETSTATUSNCP, READWRITE, struct_spppstatusncp_sz);
  _(SPPPGETIDLETO, READWRITE, struct_spppidletimeout_sz);
  _(SPPPSETIDLETO, WRITE, struct_spppidletimeout_sz);
  _(SPPPGETAUTHFAILURES, READWRITE, struct_spppauthfailurestats_sz);
  _(SPPPSETAUTHFAILURE, WRITE, struct_spppauthfailuresettings_sz);
  _(SPPPSETDNSOPTS, WRITE, struct_spppdnssettings_sz);
  _(SPPPGETDNSOPTS, READWRITE, struct_spppdnssettings_sz);
  _(SPPPGETDNSADDRS, READWRITE, struct_spppdnsaddrs_sz);
  _(SPPPSETKEEPALIVE, WRITE, struct_spppkeepalivesettings_sz);
  _(SPPPGETKEEPALIVE, READWRITE, struct_spppkeepalivesettings_sz);
  /* Entries from file: net/if_srt.h */
  _(SRT_GETNRT, READ, sizeof(unsigned int));
  _(SRT_GETRT, READWRITE, struct_srt_rt_sz);
  _(SRT_SETRT, WRITE, struct_srt_rt_sz);
  _(SRT_DELRT, WRITE, sizeof(unsigned int));
  _(SRT_SFLAGS, WRITE, sizeof(unsigned int));
  _(SRT_GFLAGS, READ, sizeof(unsigned int));
  _(SRT_SGFLAGS, READWRITE, sizeof(unsigned int));
  _(SRT_DEBUG, WRITE, sizeof(uptr));
  /* Entries from file: net/if_tap.h */
  _(TAPGIFNAME, READ, struct_ifreq_sz);
  /* Entries from file: net/if_tun.h */
  _(TUNSDEBUG, WRITE, sizeof(int));
  _(TUNGDEBUG, READ, sizeof(int));
  _(TUNSIFMODE, WRITE, sizeof(int));
  _(TUNSLMODE, WRITE, sizeof(int));
  _(TUNSIFHEAD, WRITE, sizeof(int));
  _(TUNGIFHEAD, READ, sizeof(int));
  /* Entries from file: net/pfvar.h */
  _(DIOCSTART, NONE, 0);
  _(DIOCSTOP, NONE, 0);
  _(DIOCADDRULE, READWRITE, struct_pfioc_rule_sz);
  _(DIOCGETRULES, READWRITE, struct_pfioc_rule_sz);
  _(DIOCGETRULE, READWRITE, struct_pfioc_rule_sz);
  _(DIOCSETLCK, READWRITE, sizeof(u32));
  _(DIOCCLRSTATES, READWRITE, struct_pfioc_state_kill_sz);
  _(DIOCGETSTATE, READWRITE, struct_pfioc_state_sz);
  _(DIOCSETSTATUSIF, READWRITE, struct_pfioc_if_sz);
  _(DIOCGETSTATUS, READWRITE, struct_pf_status_sz);
  _(DIOCCLRSTATUS, NONE, 0);
  _(DIOCNATLOOK, READWRITE, struct_pfioc_natlook_sz);
  _(DIOCSETDEBUG, READWRITE, sizeof(u32));
  _(DIOCGETSTATES, READWRITE, struct_pfioc_states_sz);
  _(DIOCCHANGERULE, READWRITE, struct_pfioc_rule_sz);
  _(DIOCSETTIMEOUT, READWRITE, struct_pfioc_tm_sz);
  _(DIOCGETTIMEOUT, READWRITE, struct_pfioc_tm_sz);
  _(DIOCADDSTATE, READWRITE, struct_pfioc_state_sz);
  _(DIOCCLRRULECTRS, NONE, 0);
  _(DIOCGETLIMIT, READWRITE, struct_pfioc_limit_sz);
  _(DIOCSETLIMIT, READWRITE, struct_pfioc_limit_sz);
  _(DIOCKILLSTATES, READWRITE, struct_pfioc_state_kill_sz);
  _(DIOCSTARTALTQ, NONE, 0);
  _(DIOCSTOPALTQ, NONE, 0);
  _(DIOCADDALTQ, READWRITE, struct_pfioc_altq_sz);
  _(DIOCGETALTQS, READWRITE, struct_pfioc_altq_sz);
  _(DIOCGETALTQ, READWRITE, struct_pfioc_altq_sz);
  _(DIOCCHANGEALTQ, READWRITE, struct_pfioc_altq_sz);
  _(DIOCGETQSTATS, READWRITE, struct_pfioc_qstats_sz);
  _(DIOCBEGINADDRS, READWRITE, struct_pfioc_pooladdr_sz);
  _(DIOCADDADDR, READWRITE, struct_pfioc_pooladdr_sz);
  _(DIOCGETADDRS, READWRITE, struct_pfioc_pooladdr_sz);
  _(DIOCGETADDR, READWRITE, struct_pfioc_pooladdr_sz);
  _(DIOCCHANGEADDR, READWRITE, struct_pfioc_pooladdr_sz);
  _(DIOCADDSTATES, READWRITE, struct_pfioc_states_sz);
  _(DIOCGETRULESETS, READWRITE, struct_pfioc_ruleset_sz);
  _(DIOCGETRULESET, READWRITE, struct_pfioc_ruleset_sz);
  _(DIOCRCLRTABLES, READWRITE, struct_pfioc_table_sz);
  _(DIOCRADDTABLES, READWRITE, struct_pfioc_table_sz);
  _(DIOCRDELTABLES, READWRITE, struct_pfioc_table_sz);
  _(DIOCRGETTABLES, READWRITE, struct_pfioc_table_sz);
  _(DIOCRGETTSTATS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRCLRTSTATS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRCLRADDRS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRADDADDRS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRDELADDRS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRSETADDRS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRGETADDRS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRGETASTATS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRCLRASTATS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRTSTADDRS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRSETTFLAGS, READWRITE, struct_pfioc_table_sz);
  _(DIOCRINADEFINE, READWRITE, struct_pfioc_table_sz);
  _(DIOCOSFPFLUSH, NONE, 0);
  _(DIOCOSFPADD, READWRITE, struct_pf_osfp_ioctl_sz);
  _(DIOCOSFPGET, READWRITE, struct_pf_osfp_ioctl_sz);
  _(DIOCXBEGIN, READWRITE, struct_pfioc_trans_sz);
  _(DIOCXCOMMIT, READWRITE, struct_pfioc_trans_sz);
  _(DIOCXROLLBACK, READWRITE, struct_pfioc_trans_sz);
  _(DIOCGETSRCNODES, READWRITE, struct_pfioc_src_nodes_sz);
  _(DIOCCLRSRCNODES, NONE, 0);
  _(DIOCSETHOSTID, READWRITE, sizeof(u32));
  _(DIOCIGETIFACES, READWRITE, struct_pfioc_iface_sz);
  _(DIOCSETIFFLAG, READWRITE, struct_pfioc_iface_sz);
  _(DIOCCLRIFFLAG, READWRITE, struct_pfioc_iface_sz);
  _(DIOCKILLSRCNODES, READWRITE, struct_pfioc_src_node_kill_sz);
  /* Entries from file: net/slip.h */
  _(SLIOCGUNIT, READ, sizeof(int));
  /* Entries from file: netbt/hci.h */
  _(SIOCGBTINFO, READWRITE, struct_btreq_sz);
  _(SIOCGBTINFOA, READWRITE, struct_btreq_sz);
  _(SIOCNBTINFO, READWRITE, struct_btreq_sz);
  _(SIOCSBTFLAGS, READWRITE, struct_btreq_sz);
  _(SIOCSBTPOLICY, READWRITE, struct_btreq_sz);
  _(SIOCSBTPTYPE, READWRITE, struct_btreq_sz);
  _(SIOCGBTSTATS, READWRITE, struct_btreq_sz);
  _(SIOCZBTSTATS, READWRITE, struct_btreq_sz);
  _(SIOCBTDUMP, WRITE, struct_btreq_sz);
  _(SIOCSBTSCOMTU, READWRITE, struct_btreq_sz);
  _(SIOCGBTFEAT, READWRITE, struct_btreq_sz);
  /* Entries from file: netinet/ip_nat.h */
  _(SIOCADNAT, WRITE, struct_ipfobj_sz);
  _(SIOCRMNAT, WRITE, struct_ipfobj_sz);
  _(SIOCGNATS, READWRITE, struct_ipfobj_sz);
  _(SIOCGNATL, READWRITE, struct_ipfobj_sz);
  _(SIOCPURGENAT, READWRITE, struct_ipfobj_sz);
  /* Entries from file: netinet6/in6_var.h */
  _(SIOCSIFINFO_FLAGS, READWRITE, struct_in6_ndireq_sz);
  _(SIOCAADDRCTL_POLICY, WRITE, struct_in6_addrpolicy_sz);
  _(SIOCDADDRCTL_POLICY, WRITE, struct_in6_addrpolicy_sz);
  /* Entries from file: netsmb/smb_dev.h */
  _(SMBIOC_OPENSESSION, WRITE, struct_smbioc_ossn_sz);
  _(SMBIOC_OPENSHARE, WRITE, struct_smbioc_oshare_sz);
  _(SMBIOC_REQUEST, READWRITE, struct_smbioc_rq_sz);
  _(SMBIOC_SETFLAGS, WRITE, struct_smbioc_flags_sz);
  _(SMBIOC_LOOKUP, WRITE, struct_smbioc_lookup_sz);
  _(SMBIOC_READ, READWRITE, struct_smbioc_rw_sz);
  _(SMBIOC_WRITE, READWRITE, struct_smbioc_rw_sz);
  /* Entries from file: sys/agpio.h */
  _(AGPIOC_INFO, READ, struct__agp_info_sz);
  _(AGPIOC_ACQUIRE, NONE, 0);
  _(AGPIOC_RELEASE, NONE, 0);
  _(AGPIOC_SETUP, WRITE, struct__agp_setup_sz);
  _(AGPIOC_ALLOCATE, READWRITE, struct__agp_allocate_sz);
  _(AGPIOC_DEALLOCATE, WRITE, sizeof(int));
  _(AGPIOC_BIND, WRITE, struct__agp_bind_sz);
  _(AGPIOC_UNBIND, WRITE, struct__agp_unbind_sz);
  /* Entries from file: sys/audioio.h */
  _(AUDIO_GETINFO, READ, struct_audio_info_sz);
  _(AUDIO_SETINFO, READWRITE, struct_audio_info_sz);
  _(AUDIO_DRAIN, NONE, 0);
  _(AUDIO_FLUSH, NONE, 0);
  _(AUDIO_WSEEK, READ, sizeof(unsigned long));
  _(AUDIO_RERROR, READ, sizeof(int));
  _(AUDIO_GETDEV, READ, struct_audio_device_sz);
  _(AUDIO_GETENC, READWRITE, struct_audio_encoding_sz);
  _(AUDIO_GETFD, READ, sizeof(int));
  _(AUDIO_SETFD, READWRITE, sizeof(int));
  _(AUDIO_PERROR, READ, sizeof(int));
  _(AUDIO_GETIOFFS, READ, struct_audio_offset_sz);
  _(AUDIO_GETOOFFS, READ, struct_audio_offset_sz);
  _(AUDIO_GETPROPS, READ, sizeof(int));
  _(AUDIO_GETBUFINFO, READ, struct_audio_info_sz);
  _(AUDIO_SETCHAN, WRITE, sizeof(int));
  _(AUDIO_GETCHAN, READ, sizeof(int));
  _(AUDIO_MIXER_READ, READWRITE, struct_mixer_ctrl_sz);
  _(AUDIO_MIXER_WRITE, READWRITE, struct_mixer_ctrl_sz);
  _(AUDIO_MIXER_DEVINFO, READWRITE, struct_mixer_devinfo_sz);
  /* Entries from file: sys/ataio.h */
  _(ATAIOCCOMMAND, READWRITE, struct_atareq_sz);
  _(ATABUSIOSCAN, WRITE, struct_atabusioscan_args_sz);
  _(ATABUSIORESET, NONE, 0);
  _(ATABUSIODETACH, WRITE, struct_atabusiodetach_args_sz);
  /* Entries from file: sys/cdio.h */
  _(CDIOCPLAYTRACKS, WRITE, struct_ioc_play_track_sz);
  _(CDIOCPLAYBLOCKS, WRITE, struct_ioc_play_blocks_sz);
  _(CDIOCREADSUBCHANNEL, READWRITE, struct_ioc_read_subchannel_sz);
  _(CDIOREADTOCHEADER, READ, struct_ioc_toc_header_sz);
  _(CDIOREADTOCENTRIES, READWRITE, struct_ioc_read_toc_entry_sz);
  _(CDIOREADMSADDR, READWRITE, sizeof(int));
  _(CDIOCSETPATCH, WRITE, struct_ioc_patch_sz);
  _(CDIOCGETVOL, READ, struct_ioc_vol_sz);
  _(CDIOCSETVOL, WRITE, struct_ioc_vol_sz);
  _(CDIOCSETMONO, NONE, 0);
  _(CDIOCSETSTEREO, NONE, 0);
  _(CDIOCSETMUTE, NONE, 0);
  _(CDIOCSETLEFT, NONE, 0);
  _(CDIOCSETRIGHT, NONE, 0);
  _(CDIOCSETDEBUG, NONE, 0);
  _(CDIOCCLRDEBUG, NONE, 0);
  _(CDIOCPAUSE, NONE, 0);
  _(CDIOCRESUME, NONE, 0);
  _(CDIOCRESET, NONE, 0);
  _(CDIOCSTART, NONE, 0);
  _(CDIOCSTOP, NONE, 0);
  _(CDIOCEJECT, NONE, 0);
  _(CDIOCALLOW, NONE, 0);
  _(CDIOCPREVENT, NONE, 0);
  _(CDIOCCLOSE, NONE, 0);
  _(CDIOCPLAYMSF, WRITE, struct_ioc_play_msf_sz);
  _(CDIOCLOADUNLOAD, WRITE, struct_ioc_load_unload_sz);
  /* Entries from file: sys/chio.h */
  _(CHIOMOVE, WRITE, struct_changer_move_request_sz);
  _(CHIOEXCHANGE, WRITE, struct_changer_exchange_request_sz);
  _(CHIOPOSITION, WRITE, struct_changer_position_request_sz);
  _(CHIOGPICKER, READ, sizeof(int));
  _(CHIOSPICKER, WRITE, sizeof(int));
  _(CHIOGPARAMS, READ, struct_changer_params_sz);
  _(CHIOIELEM, NONE, 0);
  _(OCHIOGSTATUS, WRITE, struct_ochanger_element_status_request_sz);
  _(CHIOGSTATUS, WRITE, struct_changer_element_status_request_sz);
  _(CHIOSVOLTAG, WRITE, struct_changer_set_voltag_request_sz);
  /* Entries from file: sys/clockctl.h */
  _(CLOCKCTL_SETTIMEOFDAY, WRITE, struct_clockctl_settimeofday_sz);
  _(CLOCKCTL_ADJTIME, READWRITE, struct_clockctl_adjtime_sz);
  _(CLOCKCTL_CLOCK_SETTIME, WRITE, struct_clockctl_clock_settime_sz);
  _(CLOCKCTL_NTP_ADJTIME, READWRITE, struct_clockctl_ntp_adjtime_sz);
  /* Entries from file: sys/cpuio.h */
  _(IOC_CPU_SETSTATE, WRITE, struct_cpustate_sz);
  _(IOC_CPU_GETSTATE, READWRITE, struct_cpustate_sz);
  _(IOC_CPU_GETCOUNT, READ, sizeof(int));
  _(IOC_CPU_MAPID, READWRITE, sizeof(int));
  _(IOC_CPU_UCODE_GET_VERSION, READWRITE, struct_cpu_ucode_version_sz);
  _(IOC_CPU_UCODE_APPLY, WRITE, struct_cpu_ucode_sz);
  /* Entries from file: sys/dkio.h */
  _(DIOCGDINFO, READ, struct_disklabel_sz);
  _(DIOCSDINFO, WRITE, struct_disklabel_sz);
  _(DIOCWDINFO, WRITE, 0);
  _(DIOCRFORMAT, READWRITE, struct_format_op_sz);
  _(DIOCWFORMAT, READWRITE, struct_format_op_sz);
  _(DIOCSSTEP, WRITE, sizeof(int));
  _(DIOCSRETRIES, WRITE, sizeof(int));
  _(DIOCKLABEL, WRITE, sizeof(int));
  _(DIOCWLABEL, WRITE, sizeof(int));
  _(DIOCSBAD, WRITE, struct_dkbad_sz);
  _(DIOCEJECT, WRITE, sizeof(int));
  _(ODIOCEJECT, NONE, 0);
  _(DIOCLOCK, WRITE, sizeof(int));
  _(DIOCGDEFLABEL, READ, struct_disklabel_sz);
  _(DIOCCLRLABEL, NONE, 0);
  _(DIOCGCACHE, READ, sizeof(int));
  _(DIOCSCACHE, WRITE, sizeof(int));
  _(DIOCCACHESYNC, WRITE, sizeof(int));
  _(DIOCBSLIST, READWRITE, struct_disk_badsecinfo_sz);
  _(DIOCBSFLUSH, NONE, 0);
  _(DIOCAWEDGE, READWRITE, struct_dkwedge_info_sz);
  _(DIOCGWEDGEINFO, READ, struct_dkwedge_info_sz);
  _(DIOCDWEDGE, WRITE, struct_dkwedge_info_sz);
  _(DIOCLWEDGES, READWRITE, struct_dkwedge_list_sz);
  _(DIOCGSTRATEGY, READ, struct_disk_strategy_sz);
  _(DIOCSSTRATEGY, WRITE, struct_disk_strategy_sz);
  _(DIOCGDISKINFO, READ, struct_plistref_sz);
  _(DIOCTUR, READ, sizeof(int));
  _(DIOCMWEDGES, READ, sizeof(int));
  _(DIOCGSECTORSIZE, READ, sizeof(unsigned int));
  _(DIOCGMEDIASIZE, READ, sizeof(uptr));
  /* Entries from file: sys/drvctlio.h */
  _(DRVDETACHDEV, WRITE, struct_devdetachargs_sz);
  _(DRVRESCANBUS, WRITE, struct_devrescanargs_sz);
  _(DRVCTLCOMMAND, READWRITE, struct_plistref_sz);
  _(DRVRESUMEDEV, WRITE, struct_devpmargs_sz);
  _(DRVLISTDEV, READWRITE, struct_devlistargs_sz);
  _(DRVGETEVENT, READ, struct_plistref_sz);
  _(DRVSUSPENDDEV, WRITE, struct_devpmargs_sz);
  /* Entries from file: sys/dvdio.h */
  _(DVD_READ_STRUCT, READWRITE, union_dvd_struct_sz);
  _(DVD_WRITE_STRUCT, READWRITE, union_dvd_struct_sz);
  _(DVD_AUTH, READWRITE, union_dvd_authinfo_sz);
  /* Entries from file: sys/envsys.h */
  _(ENVSYS_GETDICTIONARY, READWRITE, struct_plistref_sz);
  _(ENVSYS_SETDICTIONARY, READWRITE, struct_plistref_sz);
  _(ENVSYS_REMOVEPROPS, READWRITE, struct_plistref_sz);
  _(ENVSYS_GTREDATA, READWRITE, struct_envsys_tre_data_sz);
  _(ENVSYS_GTREINFO, READWRITE, struct_envsys_basic_info_sz);
  /* Entries from file: sys/event.h */
  _(KFILTER_BYFILTER, READWRITE, struct_kfilter_mapping_sz);
  _(KFILTER_BYNAME, READWRITE, struct_kfilter_mapping_sz);
  /* Entries from file: sys/fdio.h */
  _(FDIOCGETOPTS, READ, 0);
  _(FDIOCSETOPTS, WRITE, sizeof(int));
  _(FDIOCSETFORMAT, WRITE, struct_fdformat_parms_sz);
  _(FDIOCGETFORMAT, READ, struct_fdformat_parms_sz);
  _(FDIOCFORMAT_TRACK, WRITE, struct_fdformat_cmd_sz);
  /* Entries from file: sys/filio.h */
  _(FIOCLEX, NONE, 0);
  _(FIONCLEX, NONE, 0);
  _(FIONREAD, READ, sizeof(int));
  _(FIONBIO, WRITE, sizeof(int));
  _(FIOASYNC, WRITE, sizeof(int));
  _(FIOSETOWN, WRITE, sizeof(int));
  _(FIOGETOWN, READ, sizeof(int));
  _(OFIOGETBMAP, READWRITE, sizeof(u32));
  _(FIOGETBMAP, READWRITE, sizeof(u64));
  _(FIONWRITE, READ, sizeof(int));
  _(FIONSPACE, READ, sizeof(int));
  /* Entries from file: sys/gpio.h */
  _(GPIOINFO, READ, struct_gpio_info_sz);
  _(GPIOSET, READWRITE, struct_gpio_set_sz);
  _(GPIOUNSET, READWRITE, struct_gpio_set_sz);
  _(GPIOREAD, READWRITE, struct_gpio_req_sz);
  _(GPIOWRITE, READWRITE, struct_gpio_req_sz);
  _(GPIOTOGGLE, READWRITE, struct_gpio_req_sz);
  _(GPIOATTACH, READWRITE, struct_gpio_attach_sz);
  /* Entries from file: sys/ioctl.h */
  _(PTIOCNETBSD, WRITE, struct_ioctl_pt_sz);
  _(PTIOCSUNOS, WRITE, struct_ioctl_pt_sz);
  _(PTIOCLINUX, WRITE, struct_ioctl_pt_sz);
  _(PTIOCFREEBSD, WRITE, struct_ioctl_pt_sz);
  _(PTIOCULTRIX, WRITE, struct_ioctl_pt_sz);
  /* Entries from file: sys/ioctl_compat.h */
  _(TIOCHPCL, NONE, 0);
  _(TIOCGETP, READ, struct_sgttyb_sz);
  _(TIOCSETP, WRITE, struct_sgttyb_sz);
  _(TIOCSETN, WRITE, 0);
  _(TIOCSETC, WRITE, struct_tchars_sz);
  _(TIOCGETC, READ, struct_tchars_sz);
  _(TIOCLBIS, WRITE, sizeof(int));
  _(TIOCLBIC, WRITE, sizeof(int));
  _(TIOCLSET, WRITE, sizeof(int));
  _(TIOCLGET, READ, sizeof(int));
  _(TIOCSLTC, WRITE, struct_ltchars_sz);
  _(TIOCGLTC, READ, struct_ltchars_sz);
  _(OTIOCCONS, NONE, 0);
  /* Entries from file: sys/joystick.h */
  _(JOY_SETTIMEOUT, WRITE, sizeof(int));
  _(JOY_GETTIMEOUT, READ, sizeof(int));
  _(JOY_SET_X_OFFSET, WRITE, sizeof(int));
  _(JOY_SET_Y_OFFSET, WRITE, sizeof(int));
  _(JOY_GET_X_OFFSET, READ, sizeof(int));
  _(JOY_GET_Y_OFFSET, READ, sizeof(int));
  /* Entries from file: sys/ksyms.h */
  _(OKIOCGSYMBOL, WRITE, struct_ksyms_ogsymbol_sz);
  _(OKIOCGVALUE, WRITE, struct_ksyms_ogsymbol_sz);
  _(KIOCGSIZE, READ, sizeof(int));
  _(KIOCGVALUE, READWRITE, struct_ksyms_gvalue_sz);
  _(KIOCGSYMBOL, READWRITE, struct_ksyms_gsymbol_sz);
  /* Entries from file: sys/lua.h */
  _(LUAINFO, READWRITE, struct_lua_info_sz);
  _(LUACREATE, READWRITE, struct_lua_create_sz);
  _(LUADESTROY, READWRITE, struct_lua_create_sz);
  _(LUAREQUIRE, READWRITE, struct_lua_require_sz);
  _(LUALOAD, READWRITE, struct_lua_load_sz);
  /* Entries from file: sys/midiio.h */
  _(MIDI_PRETIME, READWRITE, sizeof(int));
  _(MIDI_MPUMODE, READWRITE, sizeof(int));
  _(MIDI_MPUCMD, READWRITE, struct_mpu_command_rec_sz);
  _(SEQUENCER_RESET, NONE, 0);
  _(SEQUENCER_SYNC, NONE, 0);
  _(SEQUENCER_INFO, READWRITE, struct_synth_info_sz);
  _(SEQUENCER_CTRLRATE, READWRITE, sizeof(int));
  _(SEQUENCER_GETOUTCOUNT, READ, sizeof(int));
  _(SEQUENCER_GETINCOUNT, READ, sizeof(int));
  _(SEQUENCER_RESETSAMPLES, WRITE, sizeof(int));
  _(SEQUENCER_NRSYNTHS, READ, sizeof(int));
  _(SEQUENCER_NRMIDIS, READ, sizeof(int));
  _(SEQUENCER_THRESHOLD, WRITE, sizeof(int));
  _(SEQUENCER_MEMAVL, READWRITE, sizeof(int));
  _(SEQUENCER_PANIC, NONE, 0);
  _(SEQUENCER_OUTOFBAND, WRITE, struct_seq_event_rec_sz);
  _(SEQUENCER_GETTIME, READ, sizeof(int));
  _(SEQUENCER_TMR_TIMEBASE, READWRITE, sizeof(int));
  _(SEQUENCER_TMR_START, NONE, 0);
  _(SEQUENCER_TMR_STOP, NONE, 0);
  _(SEQUENCER_TMR_CONTINUE, NONE, 0);
  _(SEQUENCER_TMR_TEMPO, READWRITE, sizeof(int));
  _(SEQUENCER_TMR_SOURCE, READWRITE, sizeof(int));
  _(SEQUENCER_TMR_METRONOME, WRITE, sizeof(int));
  _(SEQUENCER_TMR_SELECT, WRITE, sizeof(int));
  /* Entries from file: sys/mtio.h */
  _(MTIOCTOP, WRITE, struct_mtop_sz);
  _(MTIOCGET, READ, struct_mtget_sz);
  _(MTIOCIEOT, NONE, 0);
  _(MTIOCEEOT, NONE, 0);
  _(MTIOCRDSPOS, READ, sizeof(u32));
  _(MTIOCRDHPOS, READ, sizeof(u32));
  _(MTIOCSLOCATE, WRITE, sizeof(u32));
  _(MTIOCHLOCATE, WRITE, sizeof(u32));
  /* Entries from file: sys/power.h */
  _(POWER_EVENT_RECVDICT, READWRITE, struct_plistref_sz);
  _(POWER_IOC_GET_TYPE, READ, struct_power_type_sz);
  _(POWER_IOC_GET_TYPE_WITH_LOSSAGE, READ, sizeof(uptr));
  /* Entries from file: sys/radioio.h */
  _(RIOCGINFO, READ, struct_radio_info_sz);
  _(RIOCSINFO, READWRITE, struct_radio_info_sz);
  _(RIOCSSRCH, WRITE, sizeof(int));
  /* Entries from file: sys/rndio.h */
  _(RNDGETENTCNT, READ, sizeof(u32));
  _(RNDGETSRCNUM, READWRITE, struct_rndstat_sz);
  _(RNDGETSRCNAME, READWRITE, struct_rndstat_name_sz);
  _(RNDCTL, WRITE, struct_rndctl_sz);
  _(RNDADDDATA, WRITE, struct_rnddata_sz);
  _(RNDGETPOOLSTAT, READ, struct_rndpoolstat_sz);
  _(RNDGETESTNUM, READWRITE, struct_rndstat_est_sz);
  _(RNDGETESTNAME, READWRITE, struct_rndstat_est_name_sz);
  /* Entries from file: sys/scanio.h */
  _(SCIOCGET, READ, struct_scan_io_sz);
  _(SCIOCSET, WRITE, struct_scan_io_sz);
  _(SCIOCRESTART, NONE, 0);
  _(SCIOC_USE_ADF, NONE, 0);
  /* Entries from file: sys/scsiio.h */
  _(SCIOCCOMMAND, READWRITE, struct_scsireq_sz);
  _(SCIOCDEBUG, WRITE, sizeof(int));
  _(SCIOCIDENTIFY, READ, struct_scsi_addr_sz);
  _(OSCIOCIDENTIFY, READ, struct_oscsi_addr_sz);
  _(SCIOCDECONFIG, NONE, 0);
  _(SCIOCRECONFIG, NONE, 0);
  _(SCIOCRESET, NONE, 0);
  _(SCBUSIOSCAN, WRITE, struct_scbusioscan_args_sz);
  _(SCBUSIORESET, NONE, 0);
  _(SCBUSIODETACH, WRITE, struct_scbusiodetach_args_sz);
  _(SCBUSACCEL, WRITE, struct_scbusaccel_args_sz);
  _(SCBUSIOLLSCAN, NONE, 0);
  /* Entries from file: sys/sockio.h */
  _(SIOCSHIWAT, WRITE, sizeof(int));
  _(SIOCGHIWAT, READ, sizeof(int));
  _(SIOCSLOWAT, WRITE, sizeof(int));
  _(SIOCGLOWAT, READ, sizeof(int));
  _(SIOCATMARK, READ, sizeof(int));
  _(SIOCSPGRP, WRITE, sizeof(int));
  _(SIOCGPGRP, READ, sizeof(int));
  _(SIOCADDRT, WRITE, struct_ortentry_sz);
  _(SIOCDELRT, WRITE, struct_ortentry_sz);
  _(SIOCSIFADDR, WRITE, struct_ifreq_sz);
  _(SIOCGIFADDR, READWRITE, struct_ifreq_sz);
  _(SIOCSIFDSTADDR, WRITE, struct_ifreq_sz);
  _(SIOCGIFDSTADDR, READWRITE, struct_ifreq_sz);
  _(SIOCSIFFLAGS, WRITE, struct_ifreq_sz);
  _(SIOCGIFFLAGS, READWRITE, struct_ifreq_sz);
  _(SIOCGIFBRDADDR, READWRITE, struct_ifreq_sz);
  _(SIOCSIFBRDADDR, WRITE, struct_ifreq_sz);
  _(SIOCGIFCONF, READWRITE, struct_ifconf_sz);
  _(SIOCGIFNETMASK, READWRITE, struct_ifreq_sz);
  _(SIOCSIFNETMASK, WRITE, struct_ifreq_sz);
  _(SIOCGIFMETRIC, READWRITE, struct_ifreq_sz);
  _(SIOCSIFMETRIC, WRITE, struct_ifreq_sz);
  _(SIOCDIFADDR, WRITE, struct_ifreq_sz);
  _(SIOCAIFADDR, WRITE, struct_ifaliasreq_sz);
  _(SIOCGIFALIAS, READWRITE, struct_ifaliasreq_sz);
  _(SIOCGIFAFLAG_IN, READWRITE, struct_ifreq_sz);
  _(SIOCALIFADDR, WRITE, struct_if_laddrreq_sz);
  _(SIOCGLIFADDR, READWRITE, struct_if_laddrreq_sz);
  _(SIOCDLIFADDR, WRITE, struct_if_laddrreq_sz);
  _(SIOCSIFADDRPREF, WRITE, struct_if_addrprefreq_sz);
  _(SIOCGIFADDRPREF, READWRITE, struct_if_addrprefreq_sz);
  _(SIOCADDMULTI, WRITE, struct_ifreq_sz);
  _(SIOCDELMULTI, WRITE, struct_ifreq_sz);
  _(SIOCGETVIFCNT, READWRITE, struct_sioc_vif_req_sz);
  _(SIOCGETSGCNT, READWRITE, struct_sioc_sg_req_sz);
  _(SIOCSIFMEDIA, READWRITE, struct_ifreq_sz);
  _(SIOCGIFMEDIA, READWRITE, struct_ifmediareq_sz);
  _(SIOCSIFGENERIC, WRITE, struct_ifreq_sz);
  _(SIOCGIFGENERIC, READWRITE, struct_ifreq_sz);
  _(SIOCSIFPHYADDR, WRITE, struct_ifaliasreq_sz);
  _(SIOCGIFPSRCADDR, READWRITE, struct_ifreq_sz);
  _(SIOCGIFPDSTADDR, READWRITE, struct_ifreq_sz);
  _(SIOCDIFPHYADDR, WRITE, struct_ifreq_sz);
  _(SIOCSLIFPHYADDR, WRITE, struct_if_laddrreq_sz);
  _(SIOCGLIFPHYADDR, READWRITE, struct_if_laddrreq_sz);
  _(SIOCSIFMTU, WRITE, struct_ifreq_sz);
  _(SIOCGIFMTU, READWRITE, struct_ifreq_sz);
  _(SIOCSDRVSPEC, WRITE, struct_ifdrv_sz);
  _(SIOCGDRVSPEC, READWRITE, struct_ifdrv_sz);
  _(SIOCIFCREATE, WRITE, struct_ifreq_sz);
  _(SIOCIFDESTROY, WRITE, struct_ifreq_sz);
  _(SIOCIFGCLONERS, READWRITE, struct_if_clonereq_sz);
  _(SIOCGIFDLT, READWRITE, struct_ifreq_sz);
  _(SIOCGIFCAP, READWRITE, struct_ifcapreq_sz);
  _(SIOCSIFCAP, WRITE, struct_ifcapreq_sz);
  _(SIOCSVH, READWRITE, struct_ifreq_sz);
  _(SIOCGVH, READWRITE, struct_ifreq_sz);
  _(SIOCINITIFADDR, READWRITE, struct_ifaddr_sz);
  _(SIOCGIFDATA, READWRITE, struct_ifdatareq_sz);
  _(SIOCZIFDATA, READWRITE, struct_ifdatareq_sz);
  _(SIOCGLINKSTR, READWRITE, struct_ifdrv_sz);
  _(SIOCSLINKSTR, WRITE, struct_ifdrv_sz);
  _(SIOCGETHERCAP, READWRITE, struct_eccapreq_sz);
  _(SIOCGIFINDEX, READWRITE, struct_ifreq_sz);
  _(SIOCSETPFSYNC, WRITE, struct_ifreq_sz);
  _(SIOCGETPFSYNC, READWRITE, struct_ifreq_sz);
  /* Entries from file: sys/timepps.h */
  _(PPS_IOC_CREATE, NONE, 0);
  _(PPS_IOC_DESTROY, NONE, 0);
  _(PPS_IOC_SETPARAMS, WRITE, struct_pps_params_sz);
  _(PPS_IOC_GETPARAMS, READ, struct_pps_params_sz);
  _(PPS_IOC_GETCAP, READ, sizeof(int));
  _(PPS_IOC_FETCH, READWRITE, struct_pps_info_sz);
  _(PPS_IOC_KCBIND, WRITE, sizeof(int));
  /* Entries from file: sys/ttycom.h */
  _(TIOCEXCL, NONE, 0);
  _(TIOCNXCL, NONE, 0);
  _(TIOCFLUSH, WRITE, sizeof(int));
  _(TIOCGETA, READ, struct_termios_sz);
  _(TIOCSETA, WRITE, struct_termios_sz);
  _(TIOCSETAW, WRITE, 0);
  _(TIOCSETAF, WRITE, 0);
  _(TIOCGETD, READ, sizeof(int));
  _(TIOCSETD, WRITE, sizeof(int));
  _(TIOCGLINED, READ, (32 * sizeof(char)));
  _(TIOCSLINED, WRITE, (32 * sizeof(char)));
  _(TIOCSBRK, NONE, 0);
  _(TIOCCBRK, NONE, 0);
  _(TIOCSDTR, NONE, 0);
  _(TIOCCDTR, NONE, 0);
  _(TIOCGPGRP, READ, sizeof(int));
  _(TIOCSPGRP, WRITE, sizeof(int));
  _(TIOCOUTQ, READ, sizeof(int));
  _(TIOCSTI, WRITE, sizeof(char));
  _(TIOCNOTTY, NONE, 0);
  _(TIOCPKT, WRITE, sizeof(int));
  _(TIOCSTOP, NONE, 0);
  _(TIOCSTART, NONE, 0);
  _(TIOCMSET, WRITE, sizeof(int));
  _(TIOCMBIS, WRITE, sizeof(int));
  _(TIOCMBIC, WRITE, sizeof(int));
  _(TIOCMGET, READ, sizeof(int));
  _(TIOCREMOTE, WRITE, sizeof(int));
  _(TIOCGWINSZ, READ, struct_winsize_sz);
  _(TIOCSWINSZ, WRITE, struct_winsize_sz);
  _(TIOCUCNTL, WRITE, sizeof(int));
  _(TIOCSTAT, WRITE, sizeof(int));
  _(TIOCGSID, READ, sizeof(int));
  _(TIOCCONS, WRITE, sizeof(int));
  _(TIOCSCTTY, NONE, 0);
  _(TIOCEXT, WRITE, sizeof(int));
  _(TIOCSIG, NONE, 0);
  _(TIOCDRAIN, NONE, 0);
  _(TIOCGFLAGS, READ, sizeof(int));
  _(TIOCSFLAGS, WRITE, sizeof(int));
  _(TIOCDCDTIMESTAMP, READ, struct_timeval_sz);
  _(TIOCRCVFRAME, WRITE, sizeof(uptr));
  _(TIOCXMTFRAME, WRITE, sizeof(uptr));
  _(TIOCPTMGET, READ, struct_ptmget_sz);
  _(TIOCGRANTPT, NONE, 0);
  _(TIOCPTSNAME, READ, struct_ptmget_sz);
  _(TIOCSQSIZE, WRITE, sizeof(int));
  _(TIOCGQSIZE, READ, sizeof(int));
  /* Entries from file: sys/verified_exec.h */
  _(VERIEXEC_LOAD, WRITE, struct_plistref_sz);
  _(VERIEXEC_TABLESIZE, WRITE, struct_plistref_sz);
  _(VERIEXEC_DELETE, WRITE, struct_plistref_sz);
  _(VERIEXEC_QUERY, READWRITE, struct_plistref_sz);
  _(VERIEXEC_DUMP, READ, struct_plistref_sz);
  _(VERIEXEC_FLUSH, NONE, 0);
  /* Entries from file: sys/videoio.h */
  _(VIDIOC_QUERYCAP, READ, struct_v4l2_capability_sz);
  _(VIDIOC_RESERVED, NONE, 0);
  _(VIDIOC_ENUM_FMT, READWRITE, struct_v4l2_fmtdesc_sz);
  _(VIDIOC_G_FMT, READWRITE, struct_v4l2_format_sz);
  _(VIDIOC_S_FMT, READWRITE, struct_v4l2_format_sz);
  _(VIDIOC_REQBUFS, READWRITE, struct_v4l2_requestbuffers_sz);
  _(VIDIOC_QUERYBUF, READWRITE, struct_v4l2_buffer_sz);
  _(VIDIOC_G_FBUF, READ, struct_v4l2_framebuffer_sz);
  _(VIDIOC_S_FBUF, WRITE, struct_v4l2_framebuffer_sz);
  _(VIDIOC_OVERLAY, WRITE, sizeof(int));
  _(VIDIOC_QBUF, READWRITE, struct_v4l2_buffer_sz);
  _(VIDIOC_DQBUF, READWRITE, struct_v4l2_buffer_sz);
  _(VIDIOC_STREAMON, WRITE, sizeof(int));
  _(VIDIOC_STREAMOFF, WRITE, sizeof(int));
  _(VIDIOC_G_PARM, READWRITE, struct_v4l2_streamparm_sz);
  _(VIDIOC_S_PARM, READWRITE, struct_v4l2_streamparm_sz);
  _(VIDIOC_G_STD, READ, sizeof(u64));
  _(VIDIOC_S_STD, WRITE, sizeof(u64));
  _(VIDIOC_ENUMSTD, READWRITE, struct_v4l2_standard_sz);
  _(VIDIOC_ENUMINPUT, READWRITE, struct_v4l2_input_sz);
  _(VIDIOC_G_CTRL, READWRITE, struct_v4l2_control_sz);
  _(VIDIOC_S_CTRL, READWRITE, struct_v4l2_control_sz);
  _(VIDIOC_G_TUNER, READWRITE, struct_v4l2_tuner_sz);
  _(VIDIOC_S_TUNER, WRITE, struct_v4l2_tuner_sz);
  _(VIDIOC_G_AUDIO, READ, struct_v4l2_audio_sz);
  _(VIDIOC_S_AUDIO, WRITE, struct_v4l2_audio_sz);
  _(VIDIOC_QUERYCTRL, READWRITE, struct_v4l2_queryctrl_sz);
  _(VIDIOC_QUERYMENU, READWRITE, struct_v4l2_querymenu_sz);
  _(VIDIOC_G_INPUT, READ, sizeof(int));
  _(VIDIOC_S_INPUT, READWRITE, sizeof(int));
  _(VIDIOC_G_OUTPUT, READ, sizeof(int));
  _(VIDIOC_S_OUTPUT, READWRITE, sizeof(int));
  _(VIDIOC_ENUMOUTPUT, READWRITE, struct_v4l2_output_sz);
  _(VIDIOC_G_AUDOUT, READ, struct_v4l2_audioout_sz);
  _(VIDIOC_S_AUDOUT, WRITE, struct_v4l2_audioout_sz);
  _(VIDIOC_G_MODULATOR, READWRITE, struct_v4l2_modulator_sz);
  _(VIDIOC_S_MODULATOR, WRITE, struct_v4l2_modulator_sz);
  _(VIDIOC_G_FREQUENCY, READWRITE, struct_v4l2_frequency_sz);
  _(VIDIOC_S_FREQUENCY, WRITE, struct_v4l2_frequency_sz);
  _(VIDIOC_CROPCAP, READWRITE, struct_v4l2_cropcap_sz);
  _(VIDIOC_G_CROP, READWRITE, struct_v4l2_crop_sz);
  _(VIDIOC_S_CROP, WRITE, struct_v4l2_crop_sz);
  _(VIDIOC_G_JPEGCOMP, READ, struct_v4l2_jpegcompression_sz);
  _(VIDIOC_S_JPEGCOMP, WRITE, struct_v4l2_jpegcompression_sz);
  _(VIDIOC_QUERYSTD, READ, sizeof(u64));
  _(VIDIOC_TRY_FMT, READWRITE, struct_v4l2_format_sz);
  _(VIDIOC_ENUMAUDIO, READWRITE, struct_v4l2_audio_sz);
  _(VIDIOC_ENUMAUDOUT, READWRITE, struct_v4l2_audioout_sz);
  _(VIDIOC_G_PRIORITY, READ, enum_v4l2_priority_sz);
  _(VIDIOC_S_PRIORITY, WRITE, enum_v4l2_priority_sz);
  _(VIDIOC_ENUM_FRAMESIZES, READWRITE, struct_v4l2_frmsizeenum_sz);
  _(VIDIOC_ENUM_FRAMEINTERVALS, READWRITE, struct_v4l2_frmivalenum_sz);
  /* Entries from file: sys/wdog.h */
  _(WDOGIOC_GMODE, READWRITE, struct_wdog_mode_sz);
  _(WDOGIOC_SMODE, WRITE, struct_wdog_mode_sz);
  _(WDOGIOC_WHICH, READ, struct_wdog_mode_sz);
  _(WDOGIOC_TICKLE, NONE, 0);
  _(WDOGIOC_GTICKLER, READ, sizeof(int));
  _(WDOGIOC_GWDOGS, READWRITE, struct_wdog_conf_sz);
  /* Entries from file: soundcard.h */
  _(SNDCTL_DSP_RESET, NONE, 0);
  _(SNDCTL_DSP_SYNC, NONE, 0);
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
  _(SNDCTL_DSP_POST, NONE, 0);
  _(SNDCTL_DSP_SUBDIVIDE, READWRITE, sizeof(int));
  _(SNDCTL_DSP_SETFRAGMENT, READWRITE, sizeof(int));
  _(SNDCTL_DSP_GETFMTS, READ, sizeof(int));
  _(SNDCTL_DSP_GETOSPACE, READ, struct_audio_buf_info_sz);
  _(SNDCTL_DSP_GETISPACE, READ, struct_audio_buf_info_sz);
  _(SNDCTL_DSP_NONBLOCK, NONE, 0);
  _(SNDCTL_DSP_GETCAPS, READ, sizeof(int));
  _(SNDCTL_DSP_GETTRIGGER, READ, sizeof(int));
  _(SNDCTL_DSP_SETTRIGGER, WRITE, sizeof(int));
  _(SNDCTL_DSP_GETIPTR, READ, struct_count_info_sz);
  _(SNDCTL_DSP_GETOPTR, READ, struct_count_info_sz);
  _(SNDCTL_DSP_MAPINBUF, READ, struct_buffmem_desc_sz);
  _(SNDCTL_DSP_MAPOUTBUF, READ, struct_buffmem_desc_sz);
  _(SNDCTL_DSP_SETSYNCRO, NONE, 0);
  _(SNDCTL_DSP_SETDUPLEX, NONE, 0);
  _(SNDCTL_DSP_PROFILE, WRITE, sizeof(int));
  _(SNDCTL_DSP_GETODELAY, READ, sizeof(int));
  _(SOUND_MIXER_INFO, READ, struct_mixer_info_sz);
  _(SOUND_OLD_MIXER_INFO, READ, struct__old_mixer_info_sz);
  _(OSS_GETVERSION, READ, sizeof(int));
  _(SNDCTL_SYSINFO, READ, struct_oss_sysinfo_sz);
  _(SNDCTL_AUDIOINFO, READWRITE, struct_oss_audioinfo_sz);
  _(SNDCTL_ENGINEINFO, READWRITE, struct_oss_audioinfo_sz);
  _(SNDCTL_DSP_GETPLAYVOL, READ, sizeof(unsigned int));
  _(SNDCTL_DSP_SETPLAYVOL, WRITE, sizeof(unsigned int));
  _(SNDCTL_DSP_GETRECVOL, READ, sizeof(unsigned int));
  _(SNDCTL_DSP_SETRECVOL, WRITE, sizeof(unsigned int));
  _(SNDCTL_DSP_SKIP, NONE, 0);
  _(SNDCTL_DSP_SILENCE, NONE, 0);
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

#endif // SANITIZER_NETBSD
