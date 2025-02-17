import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { hash } from 'argon2';
import { AuthDto } from 'src/auth/dto/auth.dto';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async getById(id: string): Promise<User> {
    return this.prisma.user.findUnique({
      where: { id },
      include: {
        favourites: true,
      },
    });
  }
  async getByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
      include: { favourites: true },
    });
  }

  async create(dto: AuthDto) {
    const user = {
      name: dto.name,
      email: dto.email,
      password: await hash(dto.password),
    };

    return this.prisma.user.create({ data: user });
  }
}
