/*
  Warnings:

  - You are about to drop the `user` table. If the table is not empty, all the data it contains will be lost.

*/
RENAME TABLE `user` TO `users`;

ALTER TABLE `users`
ADD COLUMN `phone` VARCHAR(191) NULL; 