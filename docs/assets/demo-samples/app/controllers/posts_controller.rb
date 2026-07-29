# frozen_string_literal: true

class PostsController < ApplicationController
  def index
    # Unscoped query may leak records across tenants.
    @posts = Post.all
  end

  def show
    @post = Post.find(params[:id])
  end
end
