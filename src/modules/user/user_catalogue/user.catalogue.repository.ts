import { Injectable } from "@nestjs/common";
import { PrismaService } from "../../prisma/prisma.service";
import { BaseRepository } from "src/repositories/base.repository";
import {  UserCatalogue } from "@prisma/client";


@Injectable()
export class UserCatalogueRepository extends BaseRepository<
    typeof PrismaService.prototype.userCatalogue,
    UserCatalogue
>{
    constructor(
        private readonly prisma: PrismaService
    ){
        super(prisma.userCatalogue)
    }


}