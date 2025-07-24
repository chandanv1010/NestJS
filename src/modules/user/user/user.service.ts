import { UserRepository } from "./user.repository";
import { Injectable } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { BaseService } from "src/common/bases/base.service";
import { User } from "@prisma/client";
import { PrismaService } from "../../prisma/prisma.service";

@Injectable()
export class UserService extends BaseService<UserRepository, User> {
    private readonly userLogger = new Logger(UserService.name)


    constructor(
        private readonly userRepository: UserRepository,
        protected readonly prismaService: PrismaService
    ){
        super(userRepository, prismaService)
    }


    async findByEmail(email: string ): Promise<User | null>{
        const model = await this.userRepository.findByField('email', email)
        return model
    } 

     async findResetToken(token: string ): Promise<User | null>{
        const model = await this.userRepository.isValidResetToken(token)
        return model
    } 


}