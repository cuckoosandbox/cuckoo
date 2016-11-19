-- MySQL dump 10.13  Distrib 5.5.53, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: cuckoo
-- ------------------------------------------------------
-- Server version	5.5.53-0ubuntu0.14.04.1

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
  UNIQUE KEY `task_id` (`task_id`),
  CONSTRAINT `errors_ibfk_1` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `errors`
--

LOCK TABLES `errors` WRITE;
/*!40000 ALTER TABLE `errors` DISABLE KEYS */;
INSERT INTO `errors` VALUES (1,'hello world',1);
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
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `guests`
--

LOCK TABLES `guests` WRITE;
/*!40000 ALTER TABLE `guests` DISABLE KEYS */;
INSERT INTO `guests` VALUES (1,'cuckoo1','cuckoo7','VirtualBox','2016-11-17 02:43:02','2016-11-17 02:45:16',1),(2,'cuckoo1','cuckoo7','VirtualBox','2016-11-17 02:45:17',NULL,2);
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
  `locked` tinyint(1) NOT NULL,
  `locked_changed_on` datetime DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `status_changed_on` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `machines`
--

LOCK TABLES `machines` WRITE;
/*!40000 ALTER TABLE `machines` DISABLE KEYS */;
INSERT INTO `machines` VALUES (2,'cuckoo1','cuckoo7','192.168.56.101','windows',1,'2016-11-17 02:45:17','poweroff','2016-11-17 02:46:44');
INSERT INTO `machines` VALUES (3,'cuckoo2','cuckoo8','192.168.56.102','windows',1,null,'poweroff',null);
/*!40000 ALTER TABLE `machines` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
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
  `added_on` datetime NOT NULL,
  `started_on` datetime DEFAULT NULL,
  `completed_on` datetime DEFAULT NULL,
  `status` enum('pending','processing','failure','success') NOT NULL DEFAULT 'pending',
  `sample_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sample_id` (`sample_id`),
  CONSTRAINT `tasks_ibfk_1` FOREIGN KEY (`sample_id`) REFERENCES `samples` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tasks`
--

LOCK TABLES `tasks` WRITE;
/*!40000 ALTER TABLE `tasks` DISABLE KEYS */;
INSERT INTO `tasks` VALUES (1,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 02:42:58','2016-11-17 02:43:02','2016-11-17 02:45:17','success',1);
INSERT INTO `tasks` VALUES (2,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 02:42:59','2016-11-17 02:45:17',NULL,'processing',1);
INSERT INTO `tasks` VALUES (3,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 02:46:53',NULL,NULL,'pending',1);

/*!40000 ALTER TABLE `tasks` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2016-11-17  2:47:52
