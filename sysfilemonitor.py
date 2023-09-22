import os
import configparser
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara
import tensorflow as tf
import numpy as np

model = tf.keras.models.load_model("model/model_1.h5")
def preprocess_input(file_path):
    with open(file_path, 'rb') as file:
        pe_data = file.read()
    max_length = 2381 
    pe_data = pe_data[:max_length] + b'\x00' * (max_length - len(pe_data))
    pe_data = np.frombuffer(pe_data, dtype=np.uint8)
    pe_data = pe_data / 255.0
    input_shape = (1, max_length) 
    pe_data = pe_data.reshape(input_shape)
    return pe_data

def predict_maliciousness(file_path):
    # Check the file extension to determine if it's a PE file
    _, file_extension = os.path.splitext(file_path)
    pe_file_extensions = [
        '.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.drv', '.efi', '.com', '.pif',
        '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
        '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.msc', '.jar', '.class', '.pyd',
        '.pyc', '.pyo', '.pyw', '.pyz', '.pyzw', '.dllx', '.dll_', '.prf', '.mci', '.msu',
        '.mui', '.ocx_', '.pnp', '.ppd', '.scr_', '.shb', '.shs', '.wsc', '.wsh', '.jtd',
        '.psd', '.pif_', '.cpl_', '.mui_', '.drv_', '.ocx_', '.tsp', '.tsp_', '.ime', '.ime_',
        '.osa', '.osa_', '.rss', '.dll_', '.elevate.dll', '.dllx', '.drv_', '.ocx_', '.sys_',
        '.com_', '.chm', '.hlp', '.acm', '.ax', '.tlb', '.hxs', '.hxi', '.inf', '.inetloc',
        '.ins', '.isp', '.its', '.job', '.jse_', '.lnk', '.mad', '.maf', '.mag', '.mam',
        '.man', '.maq', '.mar', '.mas', '.mat', '.mau', '.mav', '.maw', '.mda', '.mdt',
        '.mdw', '.mdz', '.mht', '.mhtm', '.mhtml', '.mny', '.msp', '.mst', '.mui_', '.nls',
        '.oc_', '.ops', '.pal', '.pip', '.plg', '.prg', '.printerexport', '.pv', '.qpx',
        '.rll', '.sc_', '.sct', '.shd', '.shs_', '.spl', '.tmp', '.udf', '.url', '.vb',
        '.vbe_', '.vbp', '.vxd', '.wiz', '.wll', '.ws', '.wsc_', '.wsf_', '.wsh_', '.xbap',
        '.xml', '.xsl', '.xtp', '.icl', '.icl_', '.cp_', '.exe_', '.pf_', '.int', '.pif_',
        '.386', '.ocx', '.scr_', '.sys_', '.bin', '.dat', '.dll_', '.drv_', '.hex', '.lib',
        '.obj', '.pdb', '.reg', '.tlb_', '.tsp_', '.vxd_', '.sys', '.pxi', '.ocx_', '.dllx_',
        '.prx', '.rsc', '.sy_', '.wws', '.tsk', '.ime_', '.ime', '.acc', '.ac_', '.wpx',
        '.pd_', '.ec_', '.pfx', '.nls_', '.loc', '.loc_', '.hap', '.ch_', '.cht', '.pps',
        '.pml', '.prf_', '.wax', '.ps_', '.ico', '.lnk_', '.src', '.itf', '.hxa', '.kml',
        '.shb_', '.h1s', '.vcs', '.loc', '.loc_', '.api', '.scf', '.h1s_', '.winmd', '.diagcab',
        '.wpx_', '.pag', '.msp_', '.oc_', '.fls', '.il_', '.int_', '.gpd', '.sdt', '.sr_', '.sys',
        '.bsc', '.h1m', '.cp_', '.ppd_', '.gpd_', '.h1q', '.ilq', '.hpj', '.gpe', '.ic_', '.oci',
        '.vis', '.flt', '.ktx', '.hkx', '.mde', '.flx', '.mdi', '.aw_', '.p2p', '.ctl', '.tsp_', '.pps_',
        '.vbp_', '.pml_', '.tlb_', '.ss_', '.iqy', '.rpc', '.mch', '.pdb_', '.psd_', '.scr_', '.drv_',
        '.sfc', '.lrc', '.ov_', '.dif', '.fxp', '.snp', '.stl', '.reg_', '.pps_', '.sy_', '.dmp', '.grp',
        '.olb', '.xml_', '.html_', '.xla', '.rss_', '.msg_', '.oc_', '.zol', '.mspx', '.url_', '.off',
        '.prg_', '.gadget', '.pdx', '.lib_', '.utd', '.paq8f', '.g32', '.arh', '.zka', '.paq', '.dog', '.pc',
        '.wrk', '.wbf', '.pcf', '.sj_', '.g40', '.jpe_', '.gnc', '.js_', '.ldb', '.xls_', '.wpd_', '.xlsb',
        '.xlsm_', '.xlt_', '.xltm_', '.xltx_', '.doc_', '.dot_', '.ppt_', '.pot_', '.pptm_', '.dotm_',
        '.docx_', '.zip_', '.7z_', '.rar_', '.tar_', '.gz_', '.bz2_', '.xz_', '.lzma_', '.cab_', '.deb_',
        '.rpm_', '.jar_', '.war_', '.ear_', '.hlp_', '.mht_', '.chm_', '.inf_', '.ins_', '.isp_', '.its_',
        '.bat_', '.cmd_', '.com_', '.js_', '.vbe_', '.vbs_', '.vbscript_', '.wsf_', '.wsh_', '.ps1_', '.ps2_',
        '.psc1_', '.psc2_', '.psd1_', '.psm1_', '.pst_', '.adx_', '.ad_', '.ala_', '.alf_', '.amxx_', '.apl_',
        '.ash_', '.avs_', '.big_', '.bik_', '.bmc_', '.bmd_', '.bms_', '.bps_', '.bsa_', '.bsp_', '.bto_', '.chk_',
        '.col_', '.cp_', '.cs_', '.d3dbsp_', '.d3dbsp_', '.dmo_', '.dol_', '.dpl_', '.dsp_', '.du_', '.dv2_', '.dvd_', '.eaq_',
        '.epl_', '.esp_', '.etl_', '.ex_', '.f4v_', '.fag_', '.fds_', '.ff_','.flm_', '.fsh_', '.fsq_', '.gcf_', '.gho_',
        '.gps_', '.gtp_', '.h3m_', '.h4r_', '.h4r_', '.iwd_', '.lvl_', '.lrf_', '.lrf_', '.ltx_', '.m4_', '.map_', '.mcgame_',
        '.mcd_', '.mdl_', '.mddata_', '.mdmp_', '.mds_', '.min_', '.mmf_', '.mng_', '.mpp_', '.mpq_', '.mrs_', '.mrw_', '.ms2_',
        '.mskn_', '.mxp_', '.nav_', '.nca_', '.nds_', '.ndx_', '.nf_', '.nhd_', '.nif_', '.nud_', '.nxs_', '.p2z_', '.pak_',
        '.pbo_', '.pk3_', '.pk4_', '.pk_', '.pov_', '.ppf_', '.pre_', '.pt_', '.qvm_', '.qwd_', '.raw_', '.rez_', '.rgs_',
        '.rim_', '.rofl_', '.rpm_', '.scm_', '.sco_', '.sdt_', '.sg_', '.sid_', '.sima_', '.sis_', '.skp_', '.smod_', '.spt_',
        '.srep_', '.ss_', '.sud_', '.svx_', '.tax_', '.tdt_', '.te_', '.tgz_', '.tlk_', '.tpz_', '.tzm_', '.udk_', '.unr_', '.unx_',
        '.uop_', '.usx_', '.ut2_', '.ut3_', '.uz_', '.vcd_', '.vdf_', '.vfs0_', '.vfs_', '.viv_', '.vpk_', '.vtf_', '.wad_', '.wad2_',
        '.wai_', '.wba_', '.wbd_', '.wbz_', '.wcd_', '.web_', '.wms_', '.wot_', '.wpk_', '.wpl_', '.wps_', '.wtf_', '.wwd_', '.wwf_',
        '.xex_', '.xva_', '.xwp_', '.ztmp_', '.ztmp_', '.ztpl_', '.ztmp_', '.ztmp_', '.zts_', '.ztmp_',
    ]

    if file_extension.lower() in pe_file_extensions:
        preprocessed_input = preprocess_input(file_path)
        prediction = model.predict(preprocessed_input)
        
        # Set a threshold for classifying as malicious or not
        thresholds = [0.2, 0.4, 0.6, 0.8]
        labels = ["Low", "Medium", "High", "Severe", "Critical"]

        for i, threshold in enumerate(thresholds):
            if prediction <= threshold:
                return labels[i]
        
        return labels[-1]
    else:
        return "Not a PE File"

config = configparser.ConfigParser()
config.read('config.ini')

YARA_FOLDER_PATH = os.path.join(os.getcwd(), config["YARA"]["FolderName"])

file_dict = {}
i = 0

for root, _, files in os.walk(YARA_FOLDER_PATH):
    for filename in files:
        if filename.endswith(".yar") or filename.endswith(".yara"):
            file_path = os.path.join(root, filename)
            namespace = f"namespace{i}"
            file_dict[namespace] = file_path
            i += 1

try:
    rules = yara.compile(filepaths=file_dict)
except yara.Error as e:
    print(f"YARA Compilation Error: {e}")
    rules = None

# Set up logging
LOGGING_FILE_NAME = config["LOGGING"]["FileSystemLoggingName"]
LOGGING_FILE_PATH = os.path.join(os.getcwd(), LOGGING_FILE_NAME)

if not os.path.exists(LOGGING_FILE_PATH):
    open(LOGGING_FILE_PATH, "w")

logging.basicConfig(filename=LOGGING_FILE_PATH, level=logging.INFO, format='%(asctime)s - %(message)s')

# Watchdog event handler
class SystemFileHandler(FileSystemEventHandler):
    def on_moved(self, event):
        if os.path.exists(event.src_path):
            if not event.is_directory:
                logging.info(f'Moved: {event.src_path}')
            elif event.is_directory:
                logging.info(f'Moved: {event.src_path}')

    def on_created(self, event):
        if os.path.exists(event.src_path):
            if not event.is_directory:
                logging.info(f'Created: {event.src_path}')
                if rules:
                    try:
                        matches = rules.match(event.src_path)
                        if matches:
                            logging.info(f"Matched YARA rule in {event.src_path}:", end=" ")
                            for match in matches:
                                logging.info(f"Rule: {match.rule}")
                    except yara.Error as e:
                        logging.error(f"YARA Matching Error: {e}")
                prediction = predict_maliciousness(event.src_path)
                logging.info(prediction)
            elif event.is_directory:
                logging.info(f'Created: {event.src_path}')

    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f'Deleted: {event.src_path}')
        elif event.is_directory:
            logging.info(f'Deleted: {event.src_path}')

    def on_modified(self, event):
        if os.path.exists(event.src_path):
            if not event.is_directory:
                logging.info(f'Modified: {event.src_path}')
                if rules:
                    try:
                        matches = rules.match(event.src_path)
                        if matches:
                            logging.info(f"Matched YARA rule in {event.src_path}:", end=" ")
                            for match in matches:
                                logging.info(f"Rule: {match.rule}")
                    except yara.Error as e:
                        logging.error(f"YARA Matching Error: {e}")
            elif event.is_directory:
                logging.info(f'Modified: {event.src_path}')

if __name__ == "__main__":
    path = config["SYSTEM"]["PathToMonitor"]
    observer = Observer()
    observer.schedule(SystemFileHandler(), path, recursive=True if config["DEFAULT"]["MonitorSubdirectories"] == "yes" else False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()