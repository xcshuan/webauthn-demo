package database

import (
	"fmt"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
	_ "gorm.io/driver/mysql"
	_ "gorm.io/driver/sqlite"
	"net/url"
	"time"
)

type UserDB struct {
	db *gorm.DB
}

// NewDb creates a new interface to the database identified by `dsn`. Supports the following types to select the proper dialect:
//
//   - sqlite -> "file:/home/user/data.db"
//   - mysql -> "mysql://user@pass/dbname?charset=utf8&parseTime=True&loc=Local"
func NewDb(dsn string) (*UserDB, error) {
	var err error
	var db *gorm.DB
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file": // sqlite -> file:/home/user/data.db
		db, err = gorm.Open("sqlite3", dsn[7:])
	case "mysql": // mysql://user@pass/dbname?charset=utf8&parseTime=True&loc=Local
		db, err = gorm.Open("mysql", dsn[8:])
	default: // user@pass/dbname?charset=utf8&parseTime=True&loc=Local
		db, err = gorm.Open("mysql", dsn)
	}
	if err != nil {
		err = fmt.Errorf("%s - %s", err.Error(), dsn)
		return nil, err
	}

	db.LogMode(true) // log sql queries

	db.AutoMigrate(&User{})

	dbRtn := &UserDB{
		db: db,
	}
	return dbRtn, nil
}

// GetUser returns a *User by the user's username
func (db *UserDB) GetUser(name string) (*User, error) {

	user := &User{Email: name}
	if err := db.db.Where(user).First(user).Error; err != nil {
		//log.WithField("pubkey", ykid).WithError(err).Error("failed looking up YubiUser")
		return nil, fmt.Errorf("error getting user '%s': does not exist", name)
	}

	return user, nil
}

// PutUser stores a new user by the user's username
func (db *UserDB) PutUser(user *User) error {
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	err := db.db.Create(user).Error

	return err
}

func (db *UserDB) PutUserCredentials(user *User) error {
	user.UpdatedAt = time.Now()
	err := db.db.Model(&user).Updates(User{
		UpdatedAt:   time.Now(),
		Credentials: user.Credentials,
	}).Error
	if err != nil {
		log.WithError(err).Error("unable to update credentials")
	}
	return err
}
