# frozen_string_literal: true

class User < ApplicationRecord
  # Find a user by raw SQL. This is intentionally vulnerable for demo purposes.
  def self.find_by_sql_query(name)
    # Brakeman flags the next line as SQL Injection (CWE-89).
    find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
  end

  # Weak hash for passwords. Brakeman flags MD5 usage.
  def password_digest(password)
    Digest::MD5.hexdigest(password)
  end

  # A method that is never called. Brakeman reports it as unused.
  def admin?
    role == "admin"
  end
end
