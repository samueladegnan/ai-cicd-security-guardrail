# frozen_string_literal: true

class AdminController < ApplicationController
  def dashboard
    @users = User.all
  end

  # This method is intentionally unused for the demo report.
  def admin?
    current_user&.role == "admin"
  end

  # No authorization check before destroying a record.
  def destroy
    user = User.find(params[:id])
    user.destroy
    redirect_to admin_path
  end
end
