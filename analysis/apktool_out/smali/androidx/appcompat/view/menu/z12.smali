.class public final Landroidx/appcompat/view/menu/z12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/dm1;

.field public final synthetic n:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;Landroidx/appcompat/view/menu/dm1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/z12;->n:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/z12;->m:Landroidx/appcompat/view/menu/dm1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    iget-object v0, p0, Landroidx/appcompat/view/menu/z12;->n:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/dr1;->u()Landroidx/appcompat/view/menu/u62;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/zc2;->a()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->e()Landroidx/appcompat/view/menu/mf1;

    move-result-object v1

    sget-object v3, Landroidx/appcompat/view/menu/oi1;->D0:Landroidx/appcompat/view/menu/qs1;

    invoke-virtual {v1, v3}, Landroidx/appcompat/view/menu/mf1;->s(Landroidx/appcompat/view/menu/qs1;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/pu1;->J()Landroidx/appcompat/view/menu/hz1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/hz1;->y()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->M()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "Analytics storage consent denied; will not get session id"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    :cond_0
    :goto_0
    move-object v0, v2

    goto :goto_1

    :cond_1
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->b()Landroidx/appcompat/view/menu/bc;

    move-result-object v3

    invoke-interface {v3}, Landroidx/appcompat/view/menu/bc;->a()J

    move-result-wide v3

    invoke-virtual {v1, v3, v4}, Landroidx/appcompat/view/menu/pu1;->y(J)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v1

    iget-object v1, v1, Landroidx/appcompat/view/menu/pu1;->q:Landroidx/appcompat/view/menu/zu1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/zu1;->a()J

    move-result-wide v3

    const-wide/16 v5, 0x0

    cmp-long v1, v3, v5

    if-nez v1, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v0

    iget-object v0, v0, Landroidx/appcompat/view/menu/pu1;->q:Landroidx/appcompat/view/menu/zu1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/zu1;->a()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    goto :goto_1

    :cond_3
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->M()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "getSessionId has been disabled."

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    goto :goto_0

    :goto_1
    if-eqz v0, :cond_4

    iget-object v1, p0, Landroidx/appcompat/view/menu/z12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->L()Landroidx/appcompat/view/menu/t92;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/z12;->m:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v3

    invoke-virtual {v1, v2, v3, v4}, Landroidx/appcompat/view/menu/t92;->P(Landroidx/appcompat/view/menu/dm1;J)V

    return-void

    :cond_4
    :try_start_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/z12;->m:Landroidx/appcompat/view/menu/dm1;

    invoke-interface {v0, v2}, Landroidx/appcompat/view/menu/dm1;->f(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/z12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v1

    const-string v2, "getSessionId failed with exception"

    invoke-virtual {v1, v2, v0}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    return-void
.end method
