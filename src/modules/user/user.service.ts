import { UserRepository } from "./user.repository";
import { Injectable } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { BaseService } from "src/common/bases/base.service";
import { User } from "@prisma/client";

@Injectable()
export class UserService extends BaseService<UserRepository, User> {
    private readonly userLogger = new Logger(UserService.name)


    constructor(
        private readonly userRepository: UserRepository,
    ){
        super(userRepository)
    }


}