-- MySQL dump 10.14  Distrib 5.5.47-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: cuckoo11
-- ------------------------------------------------------
-- Server version	5.5.47-MariaDB-1ubuntu0.14.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `alembic_version`
--

DROP TABLE IF EXISTS `alembic_version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `alembic_version` (
  `version_num` varchar(32) NOT NULL,
  PRIMARY KEY (`version_num`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alembic_version`
--

LOCK TABLES `alembic_version` WRITE;
/*!40000 ALTER TABLE `alembic_version` DISABLE KEYS */;
INSERT INTO `alembic_version` VALUES ('263a45963c72');
/*!40000 ALTER TABLE `alembic_version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `errors`
--

DROP TABLE IF EXISTS `errors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `errors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` varchar(255) NOT NULL,
  `task_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `task_id` (`task_id`),
  CONSTRAINT `errors_ibfk_1` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `errors`
--

LOCK TABLES `errors` WRITE;
/*!40000 ALTER TABLE `errors` DISABLE KEYS */;
/*!40000 ALTER TABLE `errors` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `guests`
--

DROP TABLE IF EXISTS `guests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `guests` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `label` varchar(255) NOT NULL,
  `manager` varchar(255) NOT NULL,
  `started_on` datetime NOT NULL,
  `shutdown_on` datetime DEFAULT NULL,
  `task_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `task_id` (`task_id`),
  CONSTRAINT `guests_ibfk_1` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `guests`
--

LOCK TABLES `guests` WRITE;
/*!40000 ALTER TABLE `guests` DISABLE KEYS */;
INSERT INTO `guests` VALUES (1,'cuckoo1','cuckoo1','VirtualBox','2017-02-07 12:40:30','2017-02-07 12:40:49',1);
/*!40000 ALTER TABLE `guests` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `machines`
--

DROP TABLE IF EXISTS `machines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `machines` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `label` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `platform` varchar(255) NOT NULL,
  `interface` varchar(255) DEFAULT NULL,
  `snapshot` varchar(255) DEFAULT NULL,
  `locked` tinyint(1) NOT NULL,
  `locked_changed_on` datetime DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `status_changed_on` datetime DEFAULT NULL,
  `resultserver_ip` varchar(255) NOT NULL,
  `resultserver_port` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `machines`
--

LOCK TABLES `machines` WRITE;
/*!40000 ALTER TABLE `machines` DISABLE KEYS */;
INSERT INTO `machines` VALUES (1,'cuckoo1','cuckoo1','192.168.56.101','windows',NULL,NULL,0,'2017-02-07 12:40:49','poweroff','2017-02-07 12:40:49','192.168.56.1','2042');
/*!40000 ALTER TABLE `machines` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `machines_tags`
--

DROP TABLE IF EXISTS `machines_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `machines_tags` (
  `machine_id` int(11) DEFAULT NULL,
  `tag_id` int(11) DEFAULT NULL,
  KEY `machine_id` (`machine_id`),
  KEY `tag_id` (`tag_id`),
  CONSTRAINT `machines_tags_ibfk_1` FOREIGN KEY (`machine_id`) REFERENCES `machines` (`id`),
  CONSTRAINT `machines_tags_ibfk_2` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `machines_tags`
--

LOCK TABLES `machines_tags` WRITE;
/*!40000 ALTER TABLE `machines_tags` DISABLE KEYS */;
/*!40000 ALTER TABLE `machines_tags` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `samples`
--

DROP TABLE IF EXISTS `samples`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `samples` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `file_size` int(11) NOT NULL,
  `file_type` varchar(255) NOT NULL,
  `md5` varchar(32) NOT NULL,
  `crc32` varchar(8) NOT NULL,
  `sha1` varchar(40) NOT NULL,
  `sha256` varchar(64) NOT NULL,
  `sha512` varchar(128) NOT NULL,
  `ssdeep` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `hash_index` (`md5`,`crc32`,`sha1`,`sha256`,`sha512`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `samples`
--

LOCK TABLES `samples` WRITE;
/*!40000 ALTER TABLE `samples` DISABLE KEYS */;
INSERT INTO `samples` VALUES (1,2048,'PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows','e1590ab0ba8fa41b4b8396a7b8370154','C56B25A6','3f3617b860e16f02fc3434c511d37efc3b2db75a','212153e5e27996d1dd7d9e01921781cf6d9426aba552017ec5e30714b61e9981','3ccc2ff27b10a0b6722e98595f47fb41ff1bf5af91ade424834b00e1dae7114de8a314ebdbdc9683a2347949fb1140b8f41382800af205d47e8ce1a7803d971d',NULL);
/*!40000 ALTER TABLE `samples` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tags`
--

DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tags`
--

LOCK TABLES `tags` WRITE;
/*!40000 ALTER TABLE `tags` DISABLE KEYS */;
/*!40000 ALTER TABLE `tags` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tasks`
--

DROP TABLE IF EXISTS `tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `target` text NOT NULL,
  `category` varchar(255) NOT NULL,
  `timeout` int(11) NOT NULL DEFAULT '0',
  `priority` int(11) NOT NULL DEFAULT '1',
  `custom` varchar(255) DEFAULT NULL,
  `machine` varchar(255) DEFAULT NULL,
  `package` varchar(255) DEFAULT NULL,
  `options` varchar(255) DEFAULT NULL,
  `platform` varchar(255) DEFAULT NULL,
  `memory` tinyint(1) NOT NULL,
  `enforce_timeout` tinyint(1) NOT NULL,
  `clock` datetime NOT NULL,
  `added_on` datetime NOT NULL,
  `started_on` datetime DEFAULT NULL,
  `completed_on` datetime DEFAULT NULL,
  `status` enum('pending','running','completed','reported','recovered') NOT NULL DEFAULT 'pending',
  `sample_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sample_id` (`sample_id`),
  CONSTRAINT `tasks_ibfk_1` FOREIGN KEY (`sample_id`) REFERENCES `samples` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tasks`
--

LOCK TABLES `tasks` WRITE;
/*!40000 ALTER TABLE `tasks` DISABLE KEYS */;
INSERT INTO `tasks` VALUES (1,'/tmp/msgbox.exe','file',0,1,'custom1','','','human=1','',0,0,'2017-02-07 12:40:24','2017-02-07 12:40:24','2017-02-07 12:40:30','2017-02-07 12:40:49','reported',1),(2,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2017-02-07 12:41:07','2017-02-07 12:41:07',NULL,NULL,'pending',1);
/*!40000 ALTER TABLE `tasks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tasks_tags`
--

DROP TABLE IF EXISTS `tasks_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tasks_tags` (
  `task_id` int(11) DEFAULT NULL,
  `tag_id` int(11) DEFAULT NULL,
  KEY `task_id` (`task_id`),
  KEY `tag_id` (`tag_id`),
  CONSTRAINT `tasks_tags_ibfk_1` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`),
  CONSTRAINT `tasks_tags_ibfk_2` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tasks_tags`
--

LOCK TABLES `tasks_tags` WRITE;
/*!40000 ALTER TABLE `tasks_tags` DISABLE KEYS */;
/*!40000 ALTER TABLE `tasks_tags` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-02-07 12:41:40
