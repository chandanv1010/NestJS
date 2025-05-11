-- AlterTable
ALTER TABLE `users` ADD COLUMN `passwordResetToken` VARCHAR(191) NULL,
    ADD COLUMN `passwordResetTokenExpires` DATETIME(3) NULL;

-- RenameIndex
ALTER TABLE `users` RENAME INDEX `User_email_key` TO `users_email_key`;
