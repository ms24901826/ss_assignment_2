# Add this line at the top of your controller
require 'open-uri'

class SessionsController < ApplicationController
  before_action :set_session, only: :destroy
  skip_authentication only: %i[new create google_auth]

  layout "auth"

  def new
  end

  def create
    if user = User.authenticate_by(email: params[:email], password: params[:password])
      if user.otp_required?
        session[:mfa_user_id] = user.id
        redirect_to verify_mfa_path
      else
        @session = create_session_for(user)
        redirect_to root_path
      end
    else
      flash.now[:alert] = t(".invalid_credentials")
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    @session.destroy
    redirect_to new_session_path, notice: t(".logout_successful")
  end

  def google_auth
    auth = request.env['omniauth.auth']

    # Find or create the user by email
    user = User.find_or_initialize_by(email: auth['info']['email'])

    # Assign attributes only if it's a new user
    if user.new_record?
      user.name = auth['info']['name'].presence || 'Default Name'
      user.password = SecureRandom.hex(15)

      # Assign a default family (create if needed)
      user.family = Family.first_or_create!(name: "Default Family")

      # Attach profile image if provided
      if auth['info']['image'].present?
        user.profile_image.attach(io: URI.open(auth['info']['image']), filename: 'profile_image.jpg')
      end
    end

    if user.save
      @session = create_session_for(user)
      redirect_to root_path, notice: "Signed in with Google!"
    else
      flash[:alert] = "There was an error creating the user."
      logger.error "User creation failed: #{user.errors.full_messages}"
      redirect_to new_session_path
    end
  end

  private

    def set_session
      @session = Current.user.sessions.find(params[:id])
    end
end
