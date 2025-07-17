import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  public async getProfile(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }
}
