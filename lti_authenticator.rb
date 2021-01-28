# Discourse Authenticator class
class LTIAuthenticator < ::Auth::Authenticator
  DISCOURSE_USERNAME_MAX_LENGTH = 20

  # override hook
  def name
    'lti'
  end

  # override hook
  def register_middleware(omniauth)
    log :info, 'register_middleware'
    omniauth.provider :lti
  end

  # override hook
  # The UX we want here is that if this is the first time a learner has authenticated,
  # we'll create a new user record for them automatically (so they don't see the modal
  # for creating their own user).  A second-time learner should just be authenticated
  # and go right into Discourse.
  #
  # We've set `SiteSetting.invite_only?` to true in order to disable the "Sign up" flow
  # in Discourse.  So this code instantiates a new User record because otherwise the
  # standard flow will popup a dialog to let them change their username, and that would
  # fail to create a new user since `SiteSetting.invite_only?` is true.
  def after_authenticate(auth_token)
    log :info, 'after_authenticate'
    log :info, "after_authenticate, auth_token: #{auth_token.inspect}"
    auth_result = Auth::Result.new

    # Grab the info we need from OmniAuth
    # We also may need to modify the EdX username to conform to Discourse's username
    # validations.
    omniauth_params = auth_token[:info]
    auth_result.username = build_discourse_username omniauth_params[:email].split('@').first
    auth_result.name = omniauth_params[:fullname]
    auth_result.email = omniauth_params[:email]
    auth_result.email_valid = auth_result.email.present?
    lti_uid = auth_token[:uid]
    auth_result.extra_data = omniauth_params.merge(lti_uid: lti_uid)
    log :info, "after_authenticate, auth_result: #{auth_result.inspect}"

    # Lookup or create a new User record, requiring that both email and username match.
    # Discourse's User model patches some Rails methods, so we use their
    # methods here rather than reaching into details of how these fields are stored in the DB.
    # This appears related to changes in https://github.com/discourse/discourse/pull/4977
    user_by_email = User.find_by_email(auth_result.email.downcase)
    user_by_username = User.find_by_username(auth_result.username)
    group_by_name = Group.find_by(name: omniauth_params[:context_label])
    ins_group_by_name = Group.find_by(name: omniauth_params[:context_label]+ '_INSTRUCTORS')
    category_by_name = Category.find_by_slug_path(omniauth_params[:context_label])
    both_matches_found = user_by_email.present? && user_by_username.present?
    no_matches_found = user_by_email.nil? && user_by_username.nil?
    no_groups = group_by_name.nil? && ins_group_by_name.nil?
    if both_matches_found && user_by_email.id == user_by_username.id
      log :info, "after_authenticate, found user records by both username and email and they matched, using existing user..."
      user = user_by_email
    elsif no_matches_found
      log :info, "after_authenticate, no matches found for email or username, creating user record for first-time user..."
      user = User.new(email: auth_result.email.downcase, username: auth_result.username, name: auth_result.name, )
      user.staged = false
      user.active = true
      user.password = SecureRandom.hex(32)
      user.save!
      user.reload
    else
      log :info, "after_authenticate, found user records that did not match by username and email"
      log :info, "after_authenticate, user_by_email: #{user_by_email.inspect}"
      log :info, "after_authenticate, user_by_username: #{user_by_username.inspect}"
      raise ::ActiveRecord::RecordInvalid('LTIAuthenticator: edge case for finding User records where username and email did not match, aborting...')
    end

    if no_groups
      main_group = Group.new(name: omniauth_params[:context_label], title: omniauth_params[:context_title])
      main_group.visibility_level = 4
      main_group.save!
      main_group.reload

      ins_group = Group.new(name: omniauth_params[:context_label] + '_INSTRUCTORS', title: omniauth_params[:context_title] + 'Instructors')
      ins_group.visibility_level = 4
      ins_group.save!
      ins_group.reload

      category = Category.new(name: omniauth_params[:context_title], slug: omniauth_params[:context_label])
      category.reviewable_by_group_id = ins_group.id
      category.save!
      category.reload

      cat_group_main = CategoryGroup.new(category_id: category.id, group_id: main_group.id)
      cat_group_ins = CategoryGroup.new(category_id: category.id, group_id: ins_group.id)

      cat_group_main.save!
      cat_group_main.reload
      cat_group_ins.save!
      cat_group_ins.reload
    end

    group_by_name = Group.find_by(name: omniauth_params[:context_label])
    ins_group_by_name = Group.find_by(name: omniauth_params[:context_label]+ '_INSTRUCTORS')

    if omniauth_params[:roles].include? "Instructor"
      g_user = GroupUser.new(group_id: ins_group_by_name.id, user_id: user.id)
      g_user.save!
      g_user.reload
    else
      g_user = GroupUser.new(group_id: group_by_name.id, user_id: user.id)
      g_user.save!
      g_user.reload
    end


    # Return a reference to the User record.
    auth_result.user = user
    log :info, "after_authenticate, user: #{auth_result.user.inspect}"

    # This isn't needed for authentication, it just tracks the unique EdX user ids
    # in a way we could look them up from the EdX username if we needed to.
    plugin_store_key = "lti_username_#{auth_result.username}"
    ::PluginStore.set('lti', plugin_store_key, auth_result.as_json)
    log :info, "after_authenticate, PluginStore.set for auth_result: #{auth_result.as_json}"

    auth_result
  end

  protected
  def log(method_symbol, text)
    Rails.logger.send(method_symbol, "LTIAuthenticator: #{text}")
  end

  # Take valid EdX usernames that would be invalid Discourse usernames, and transform
  # them into valid Discourse usernames.
  # Right now this method just handles the cases we've run into in the wild -
  # Discourse usernames can't be too long, can't end on special symbol (_) and
  # can't contain more than 1 underscore in a row.
  # See https://github.com/discourse/discourse/blob/v1.9.0.beta17/app/models/username_validator.rb#L29 for
  # full details on Discourse validation.
  #
  # This method can lead to collapsing different EdX usernames into the same Discourse
  # username (eg, kevin__robinson and kevin_robinson), but the authentication methods above
  # require that email addresses match exactly as well.
  def build_discourse_username(edx_username)
    edx_username.slice(0, DISCOURSE_USERNAME_MAX_LENGTH).gsub('__','_').chomp('_')
  end
end
