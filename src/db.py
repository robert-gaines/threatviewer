from sqlalchemy import create_engine, text
from src.ingest import IngestFeeds
import logging
import yaml
import sys
import os

logging.basicConfig(level=logging.INFO)


class DBMethods():

    def __init__(self):
        self.ingest = IngestFeeds()
        self.ingest.read_configuration()
        self.ingest.retrieve_maps()
        self.host = ""
        self.port = ""
        self.user = ""
        self.timeout = ""
        self.password = ""
        self.database = ""
        self.mysql_connstr = ""
        self.mysql_dbconnstr = ""    

    def check_configuration(self) -> bool:
        """ Check for the configuration file """
        main_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(main_dir, 'src', 'configuration.yaml')
        return os.path.exists(config_path)

    def create_session(self) -> None:
        """ Create a session to the database """
        try:
            logging.info("Creating session")
            self.engine = create_engine(
                self.mysql_connstr,
                pool_recycle=self.timeout)
            if self.engine:
                logging.info("Session created")
                return self.engine
        except Exception as e:
            logging.error("Session creation exception: {0}".format(e))
            sys.exit()

    def create_dbsession(self) -> None:
        """ Create a session to the database """
        try:
            logging.info("Creating session")
            self.engine = create_engine(
                self.mysql_dbconnstr,
                pool_recycle=self.timeout)
            if self.engine:
                logging.info("Session created")
                return self.engine
        except Exception as e:
            logging.error("Session creation exception: {0}".format(e))
            sys.exit()

    def convert_data_types(self, data):
        for row in data:
            row['TOR_Node'] = \
                1 if str(row['TOR_Node']).lower() == 'true' else 0
            row['Hostnames'] = row['Hostnames'] \
                if row['Hostnames'] else '[]'
            row['Threat_Score'] = float(row['Threat_Score']) \
                if row['Threat_Score'] else None
            row['ASN'] = int(float(row['ASN'])) \
                if row['ASN'] else None
            row['Latitude'] = float(row['Latitude']) \
                if row['Latitude'] else None
            row['Longitude'] = float(row['Longitude']) \
                if row['Longitude'] else None
        return data

    def read_configuration(self) -> None:
        """ Read the configuration file """
        try:
            if self.check_configuration():
                logging.info("Located configuration")
                main_dir = os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__)))
                config_path = os.path.join(main_dir, 'src',
                                           'configuration.yaml')
                with open(config_path, 'r') as file:
                    configuration = yaml.safe_load(file)
                configuration = configuration['db']
                self.host = configuration['host']
                self.port = configuration['port']
                self.user = configuration['user']
                self.timeout = configuration['timeout']
                self.password = configuration['password']
                self.database = configuration['database']
                self.mysql_connstr = (
                    "mysql+pymysql://{0}:{1}@{2}:{3}/"
                    .format(self.user,
                            self.password,
                            self.host,
                            self.port))
                self.mysql_dbconnstr = (
                    "mysql+pymysql://{0}:{1}@{2}:{3}/{4}"
                    .format(self.user,
                            self.password,
                            self.host,
                            self.port,
                            self.database))
            else:
                logging.error("Configuration file not found")
                sys.exit()
        except yaml.YAMLError as e:
            logging.error("Configuration intake exception: {0}".format(e))
            sys.exit()

    def drop_database(self):
        engine = self.create_session()
        if engine:
            try:
                with engine.connect() as connection:
                    connection.execute(text(
                        "DROP DATABASE {0}".format(self.database)))
                    logging.info("Database dropped")
            except Exception as e:
                print("Error connecting to the database:", e)

    def check_database(self):
        engine = self.create_session()
        if engine:
            try:
                with engine.connect() as connection:
                    result = connection.execute(text("SHOW DATABASES"))
                    results = result.fetchall()
                    databases = [db[0] for db in results]
                    if self.database in databases:
                        logging.info("Database exists")
                        return
                    else:
                        logging.info("Database does not exist")
                        logging.info("Creating database")
                        result = connection.execute(text(
                            "CREATE DATABASE {0}".format(self.database)))
                        logging.info("Database created")
            except Exception as e:
                logging.exception("Error connecting to the database:", e)

    def create_honeypot_visitors_table(self) -> None:
        engine = self.create_dbsession()
        if engine:
            try:
                with engine.connect() as connection:
                    connection.execute(text("""
                        CREATE TABLE IF NOT EXISTS honeypot_visitors (
                            IP VARCHAR(15) NOT NULL,
                            Threat_Score INT,
                            TOR_Node TINYINT,
                            Hostnames VARCHAR(255),
                            Domain VARCHAR(255),
                            ASN INT,
                            ISP VARCHAR(255),
                            City VARCHAR(255),
                            Postal VARCHAR(20),
                            Country VARCHAR(255),
                            Continent VARCHAR(255),
                            Latitude DECIMAL(10, 7),
                            Longitude DECIMAL(10, 7),
                            MarkerColor VARCHAR(50),
                            PRIMARY KEY (IP)
                        )
                    """))
                logging.info("Created honeypot_visitors table")
            except Exception as e:
                logging.error(
                    "Error creating honeypot_visitors table: {0}".format(e))

    def create_malware_hashes_table(self) -> None:
        engine = self.create_dbsession()
        if engine:
            try:
                with engine.connect() as connection:
                    connection.execute(text("""
                        CREATE TABLE IF NOT EXISTS malware_hashes (
                            TimeStamp VARCHAR(255),
                            FileName VARCHAR(255),
                            SHA256 VARCHAR(255),
                            OriginAddress VARCHAR(255),
                            PRIMARY KEY (TimeStamp)
                        )
                    """))
                logging.info("Created malware_hashes table")
            except Exception as e:
                logging.error(
                    "Error creating malware_hashes table: {0}".format(e))

    def retrieve_composite_feed(self) -> list:
        engine = self.create_dbsession()
        if engine:
            try:
                with engine.connect() as connection:
                    result = connection.execute(text(
                        "SELECT * FROM honeypot_visitors"))
                    results = result.fetchall()
                    return results
            except Exception as e:
                logging.error(
                    "Error retrieving composite feed data: {0}".format(e))

    def retrieve_malware_hashes(self) -> list:
        engine = self.create_dbsession()
        if engine:
            try:
                with engine.connect() as connection:
                    result = connection.execute(text(
                        "SELECT * FROM malware_hashes"))
                    results = result.fetchall()
                    return results
            except Exception as e:
                logging.error(
                    "Error retrieving malware hashes data: {0}".format(e))

    def insert_honeypot_visitors(self) -> None:
        data = self.ingest.retrieve_csv_from_url(self.ingest.feed)
        data = self.convert_data_types(data)
        engine = self.create_dbsession()
        if engine:
            try:
                with engine.connect() as connection:
                    for row in data:
                        result = connection.execute(text("""
                        SELECT 1 FROM honeypot_visitors WHERE IP = :IP
                        """), {'IP': row['IP']})
                        exists = result.fetchone() is not None
                        if not exists:
                            result = connection.execute(text("""
                                INSERT INTO honeypot_visitors (
                                    IP,
                                    Threat_Score,
                                    TOR_Node,
                                    Hostnames,
                                    Domain,
                                    ASN,
                                    ISP,
                                    City,
                                    Postal,
                                    Country,
                                    Continent,
                                    Latitude,
                                    Longitude,
                                    MarkerColor
                                ) VALUES (
                                    :IP,
                                    :Threat_Score,
                                    :TOR_Node,
                                    :Hostnames,
                                    :Domain,
                                    :ASN,
                                    :ISP,
                                    :City,
                                    :Postal,
                                    :Country,
                                    :Continent,
                                    :Latitude,
                                    :Longitude,
                                    :MarkerColor
                                )
                            """), row)
                            logging.info(
                                    "Inserted record for IP: {0}".format(
                                        row['IP']))
                    connection.execute(text("COMMIT"))
                logging.info("Inserted honeypot_visitors data")
            except Exception as e:
                logging.error(
                    "Error inserting honeypot_visitors data: {0}".format(e))

    def insert_malware_hashes(self) -> None:
        data = self.ingest.retrieve_csv_from_url(self.ingest.malware)
        engine = self.create_dbsession()
        if engine:
            try:
                with engine.connect() as connection:
                    for row in data:
                        result = connection.execute(text("""
                        SELECT 1 FROM malware_hashes WHERE TimeStamp
                                                         = :TimeStamp
                        """), {'TimeStamp': row['TimeStamp']})
                        exists = result.fetchone() is not None
                        if not exists:
                            result = connection.execute(text("""
                                INSERT INTO malware_hashes (
                                    TimeStamp,
                                    FileName,
                                    SHA256,
                                    OriginAddress
                                ) VALUES (
                                    :TimeStamp,
                                    :FileName,
                                    :SHA256,
                                    :OriginAddress
                                )
                            """), row)
                            logging.info(
                                    "Inserted record: {0}".format(
                                        row['OriginAddress']))
                    connection.execute(text("COMMIT"))
                logging.info("Inserted malware_hashes data")
            except Exception as e:
                logging.error(
                    "Error inserting malware_hashes data: {0}".format(e))

    def create_tables(self) -> None:
        self.check_database()
        self.create_honeypot_visitors_table()
        self.create_malware_hashes_table()

    def synchronize_data(self) -> None:
        self.insert_honeypot_visitors()
        self.insert_malware_hashes()
