class User < ActiveRecord::Base
  attr_accessible :email, :password, :password_confirmation, :password_hash, :password_salt



  #before_save { |user| user.email = email.downcase }
  before_save :encrypt_password

    attr_accessor :password
    before_save :encrypt_password

    validates_confirmation_of :password
    validates_presence_of :password, :on => :create
    validates_presence_of :email
    validates_uniqueness_of :email

  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, :presence => true, :format => { :with => VALID_EMAIL_REGEX }, :uniqueness => true

  validates :password, :presence => true, :length => { :minimum => 6 }

    def self.authenticate(email, password)
      user = find_by_email(email)
      if user && user.password_hash == BCrypt::Engine.hash_secret(password, user.password_salt)
        user
      else
        nil
      end
    end

    def encrypt_password
      if password.present?
        self.password_salt = BCrypt::Engine.generate_salt
        self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
      end
    end
  end



