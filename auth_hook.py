#from wrk.custom_hooks.zap_auth_custo.zap_auth_custo import ZapAuthCusto

import sys
sys.path.append('/zap/wrk/custom_hooks')
import zap_auth_custo
import zap_config_custo
import zap_blindxss
import os
import traceback
import logging




config = zap_config_custo.ZapConfigCusto()

# Triggered when running a script directly (ex. python zap-baseline.py ...)
def start_docker_zap(docker_image, port, extra_zap_params, mount_dir):
    config.load_config(extra_zap_params)
    logging.info("****** zap extra_zap_params: %s",extra_zap_params)

# Triggered when running from the Docker image
def start_zap(port, extra_zap_params):
    config.load_config(extra_zap_params)
    logging.info("******from the Docker image, extra_zap_params: %s",extra_zap_params)

def zap_started(zap, target):
    logging.info("******zap_started zap config: %s",config)
    try:
        # ZAP Docker scripts reset the target to the root URL
        if target.count('/') > 2:
            # The url can include a valid path, but always reset to spider the host
            target = target[0:target.index('/', 8)+1]

        scan_policy = 'Default Policy'
        zap.ascan.update_scan_policy(scanpolicyname=scan_policy , attackstrength="LOW")
        
        auth = zap_auth_custo.ZapAuthCusto(config)
        auth.authenticate(zap, target)

        zap_blindxss.load(config, zap)
    except Exception:
        logging.error("error in zap_started: %s", traceback.print_exc())
        os._exit(1)

    return zap, target

def zap_pre_shutdown(zap):
    logging.debug("Overview of spidered URL's:")
    for url in zap.spider.all_urls:
        logging.debug("found: %s", url)
    
    for result in zap.ajaxSpider.full_results['inScope']:
        logging.debug("found: %s", result['url'])
