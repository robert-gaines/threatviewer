
from io import StringIO
import requests
import logging
import yaml
import csv
import sys
import os

logging.basicConfig(level=logging.INFO)


class IngestFeeds():

    def __init__(self):
        self.feed = ''
        self.malware = ''
        self.threat_map = ''
        self.malware_map = ''

    def check_configuration(self) -> bool:
        """ Check for the configuration file """
        main_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(main_dir, 'src', 'configuration.yaml')
        return os.path.exists(config_path)

    def read_configuration(self) -> None:
        """ Read the configuration file """
        try:
            if self.check_configuration():
                main_dir = os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__)))
                config_path = os.path.join(main_dir, 'src',
                                           'configuration.yaml')
                logging.info("Located configuration")
                with open(config_path, 'r') as file:
                    configuration = yaml.safe_load(file)
                configuration = configuration['feeds']
                self.feed = configuration['composite_ip']
                self.malware = configuration['composite_malware']
                self.threat_map = configuration['threat_map']
                self.malware_map = configuration['malware_map']
        except Exception as e:
            logging.error("Configuration read exception: {0}".format(e))
            sys.exit()

    def retrieve_csv_from_url(self, url: str) -> list:
        """ Retrieve a CSV from the TI bucket """
        try:
            response = requests.get(url)
            response.raise_for_status()
            csv_content = response.text
            csv_reader = csv.DictReader(StringIO(csv_content))
            data = [row for row in csv_reader]
            logging.info("CSV file retrieved and parsed successfully")
            return data
        except Exception as e:
            logging.error("Error retrieving/parsing CSV: {0}".format(e))
            sys.exit()

    def retrieve_maps(self) -> tuple:
        """ Retrieve the composite feed and malware feed """
        try:
            static_dir = 'static'
            if not os.path.exists(static_dir):
                return
            save_path = os.path.join(static_dir, 'threatmap.html')
            response = requests.get(self.threat_map)
            response.raise_for_status() 
            with open(save_path, 'wb') as file:
                file.write(response.content)
            save_path = os.path.join(static_dir, 'malware.html')
            response = requests.get(self.malware_map)
            response.raise_for_status() 
            with open(save_path, 'wb') as file:
                file.write(response.content)
        except Exception as e:
            logging.error("Error retrieving threat map: {0}".format(e))
            sys.exit()
