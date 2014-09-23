USE oat_db;

CREATE TABLE `PCR_manifest` (
  `index` int(11) NOT NULL AUTO_INCREMENT,
  `PCR_number` int(11) DEFAULT NULL,
  `PCR_value` varchar(100) DEFAULT NULL,
  `PCR_desc` varchar(100) DEFAULT NULL,
  `create_time` datetime DEFAULT NULL,
  `create_request_host` varchar(50) DEFAULT NULL,
  `last_update_time` datetime DEFAULT NULL,
  `last_update_request_host` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`index`),
  UNIQUE KEY `PCR_UNIQUE` (`PCR_number`,`PCR_value`)
);



/*==============================================================*/
/* DBMS name:      MySQL 5.0                                    */
/* Created on:     2012/9/7 10:13:55                            */
/*==============================================================*/


drop table if exists HOST;

drop table if exists MLE;

drop table if exists OEM;

drop table if exists OS;

drop table if exists PCR_WHITE_LIST;

drop table if exists USERS_PERMISSIONS;

drop table if exists PERMISSIONS_TYPES;

drop table if exists USERS;

/*==============================================================*/
/* Table: HOST                                                  */
/*==============================================================*/
create table HOST
(
   ID                   int not null auto_increment,
   HOST_NAME            varchar(50),
   IP_ADDRESS           varchar(50),
   PORT                 varchar(50),
   EMAIL                varchar(100),
   ADDON_CONNECTION_STRING varchar(100),
   DESCRIPTION          varchar(100),
   primary key (ID)
);

/*==============================================================*/
/* Table: MLE                                                   */
/*==============================================================*/
create table MLE
(
   ID                   int not null auto_increment,
   OEM_ID               int,
   OS_ID                int,
   NAME                 varchar(50),
   VERSION              varchar(100),
   ATTESTATION_TYPE     varchar(50),
   MLE_TYPE             varchar(50),
   DESCRIPTION          varchar(100),
   primary key (ID)
);

/*==============================================================*/
/* Table: HOST_MLE                                              */
/*==============================================================*/
create table HOST_MLE
(
   ID int not null auto_increment,
   HOST_ID int ,
   MLE_ID int ,
   primary key (ID) ,
   FOREIGN KEY (HOST_ID) REFERENCES HOST(ID) ON DELETE CASCADE ,
   CONSTRAINT mle_fk FOREIGN KEY (MLE_ID) REFERENCES MLE(ID)
);


/*==============================================================*/
/* Table: OEM                                                   */
/*==============================================================*/
create table OEM
(
   ID                   int not null auto_increment,
   NAME                 varchar(50),
   DESCRIPTION          varchar(100),
   primary key (ID)
);

/*==============================================================*/
/* Table: OS                                                    */
/*==============================================================*/
create table OS
(
   ID                   int not null auto_increment,
   NAME                 varchar(50),
   VERSION              varchar(50),
   DESCRIPTION          varchar(100),
   primary key (ID)
);

/*==============================================================*/
/* Table: PCR_WHITE_LIST                                        */
/*==============================================================*/
create table PCR_WHITE_LIST
(
   ID                   int not null auto_increment,
   MLE_ID               int,
   PCR_NAME             varchar(10),
   PCR_DIGEST           varchar(100) default NULL,
   primary key (ID)
);

/*==============================================================*/
/* Table: USERS                                                 */
/*==============================================================*/
create table USERS
(
   ID                   int not null auto_increment,
   USERNAME             varchar(50),
   PASSWORD             varchar(40),
   DELETED              tinyint(1),
   primary key (ID)
);

CREATE TABLE `attest_request` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `request_id` varchar(50) DEFAULT NULL,
  `host_name` varchar(50) DEFAULT NULL,
  `request_time` datetime DEFAULT NULL,
  `next_action` int(11) DEFAULT NULL,
  `is_consumed_by_pollingWS` tinyint(1) DEFAULT NULL,
  `audit_log_id` int(11) DEFAULT NULL,
  `host_id` int(11) DEFAULT NULL,
  `request_host` varchar(50) DEFAULT NULL,
  `count` int(11) DEFAULT NULL,
  `PCRMask` varchar(50) DEFAULT NULL,
  `result` int(11) DEFAULT NULL,
  `is_sync` tinyint(1) DEFAULT NULL,
  `validate_time` datetime DEFAULT NULL,
  `id_users` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_audit_log_id` (`audit_log_id`),
  KEY `UNIQUE` (`request_id`,`host_id`),
  FOREIGN KEY (`id_users`) REFERENCES USERS(ID)
);

/*==============================================================*/
/* Table: PERMISSIONS_TYPES                                     */
/*==============================================================*/
create table PERMISSIONS_TYPES
(
   ID                   int not null auto_increment,
   CLASS                varchar(100),
   OPERATION            varchar(100),
   PAR_NAME             varchar(100),
   IS_ENFORCED          tinyint(1),
   primary key (ID),
   UNIQUE (CLASS, OPERATION, PAR_NAME)
);

INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("Host", "Read_Report", "HostName", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("Host", "Attest", "HostName", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("Host", "Read_Attest", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("User", "Add", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("User", "Add", "Password", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("User", "Edit", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("User", "Edit", "Password", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("User", "Delete", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Add", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Add", "Class", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Add", "Operation", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Add", "ParName", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Add", "Value", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Edit", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Edit", "Class", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Edit", "Operation", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Edit", "ParName", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Edit", "Value", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Delete", "Username", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Delete", "Class", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Delete", "Operation", 0);
INSERT INTO PERMISSIONS_TYPES (CLASS, OPERATION, PAR_NAME, IS_ENFORCED) VALUES ("UserPermission", "Delete", "ParName", 0);

/*==============================================================*/
/* Table: USERS_PERMISSIONS                                     */
/*==============================================================*/
create table USERS_PERMISSIONS
(
   ID                   int not null auto_increment,
   ID_USERS             int not null,
   ID_PERMISSIONS_TYPES int not null,
   VALUE                varchar(100),
   primary key (ID),
   UNIQUE (ID_USERS, ID_PERMISSIONS_TYPES) ,
   FOREIGN KEY (ID_USERS) REFERENCES USERS(ID) ON DELETE CASCADE ,
   FOREIGN KEY (ID_PERMISSIONS_TYPES) REFERENCES PERMISSIONS_TYPES(ID) ON DELETE CASCADE
);

/*==============================================================*/
/* End 								                            */
/*==============================================================*/
