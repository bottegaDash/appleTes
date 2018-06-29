class AddPostHourRequestToPosts < ActiveRecord::Migration[5.2]
  def change
    add_column :posts, :overtime_request, :decimal
  end
end
