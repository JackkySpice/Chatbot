.class public final Landroidx/appcompat/view/menu/r32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroid/os/Bundle;

.field public final synthetic n:Landroidx/appcompat/view/menu/p32;

.field public final synthetic o:Landroidx/appcompat/view/menu/p32;

.field public final synthetic p:J

.field public final synthetic q:Landroidx/appcompat/view/menu/n32;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/n32;Landroid/os/Bundle;Landroidx/appcompat/view/menu/p32;Landroidx/appcompat/view/menu/p32;J)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/r32;->q:Landroidx/appcompat/view/menu/n32;

    iput-object p2, p0, Landroidx/appcompat/view/menu/r32;->m:Landroid/os/Bundle;

    iput-object p3, p0, Landroidx/appcompat/view/menu/r32;->n:Landroidx/appcompat/view/menu/p32;

    iput-object p4, p0, Landroidx/appcompat/view/menu/r32;->o:Landroidx/appcompat/view/menu/p32;

    iput-wide p5, p0, Landroidx/appcompat/view/menu/r32;->p:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    iget-object v0, p0, Landroidx/appcompat/view/menu/r32;->q:Landroidx/appcompat/view/menu/n32;

    iget-object v1, p0, Landroidx/appcompat/view/menu/r32;->m:Landroid/os/Bundle;

    iget-object v2, p0, Landroidx/appcompat/view/menu/r32;->n:Landroidx/appcompat/view/menu/p32;

    iget-object v3, p0, Landroidx/appcompat/view/menu/r32;->o:Landroidx/appcompat/view/menu/p32;

    iget-wide v4, p0, Landroidx/appcompat/view/menu/r32;->p:J

    invoke-static/range {v0 .. v5}, Landroidx/appcompat/view/menu/n32;->J(Landroidx/appcompat/view/menu/n32;Landroid/os/Bundle;Landroidx/appcompat/view/menu/p32;Landroidx/appcompat/view/menu/p32;J)V

    return-void
.end method
