.class public final Landroidx/appcompat/view/menu/b42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:J

.field public final synthetic n:Landroidx/appcompat/view/menu/n32;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/n32;J)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/b42;->n:Landroidx/appcompat/view/menu/n32;

    iput-wide p2, p0, Landroidx/appcompat/view/menu/b42;->m:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/b42;->n:Landroidx/appcompat/view/menu/n32;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/dr1;->o()Landroidx/appcompat/view/menu/kh1;

    move-result-object v0

    iget-wide v1, p0, Landroidx/appcompat/view/menu/b42;->m:J

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/kh1;->v(J)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/b42;->n:Landroidx/appcompat/view/menu/n32;

    const/4 v1, 0x0

    iput-object v1, v0, Landroidx/appcompat/view/menu/n32;->e:Landroidx/appcompat/view/menu/p32;

    return-void
.end method
