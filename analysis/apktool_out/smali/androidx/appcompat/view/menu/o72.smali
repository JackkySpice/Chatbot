.class public final synthetic Landroidx/appcompat/view/menu/o72;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public synthetic m:Landroidx/appcompat/view/menu/i72;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/i72;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/o72;->m:Landroidx/appcompat/view/menu/i72;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    iget-object v0, p0, Landroidx/appcompat/view/menu/o72;->m:Landroidx/appcompat/view/menu/i72;

    iget-object v1, v0, Landroidx/appcompat/view/menu/i72;->o:Landroidx/appcompat/view/menu/k72;

    iget-wide v5, v0, Landroidx/appcompat/view/menu/i72;->m:J

    iget-wide v2, v0, Landroidx/appcompat/view/menu/i72;->n:J

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->n()V

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->F()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v4, "Application going to the background"

    invoke-virtual {v0, v4}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v0

    iget-object v0, v0, Landroidx/appcompat/view/menu/pu1;->s:Landroidx/appcompat/view/menu/vu1;

    const/4 v4, 0x1

    invoke-virtual {v0, v4}, Landroidx/appcompat/view/menu/vu1;->a(Z)V

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0, v4}, Landroidx/appcompat/view/menu/u62;->D(Z)V

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->e()Landroidx/appcompat/view/menu/mf1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/mf1;->Q()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u62;->f:Landroidx/appcompat/view/menu/m72;

    invoke-virtual {v0, v2, v3}, Landroidx/appcompat/view/menu/m72;->e(J)V

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    const/4 v4, 0x0

    invoke-virtual {v0, v4, v4, v2, v3}, Landroidx/appcompat/view/menu/u62;->E(ZZJ)Z

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/uc2;->a()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->e()Landroidx/appcompat/view/menu/mf1;

    move-result-object v0

    sget-object v2, Landroidx/appcompat/view/menu/oi1;->K0:Landroidx/appcompat/view/menu/qs1;

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/mf1;->s(Landroidx/appcompat/view/menu/qs1;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->J()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "Application backgrounded at: timestamp_millis"

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    return-void

    :cond_1
    iget-object v0, v1, Landroidx/appcompat/view/menu/k72;->b:Landroidx/appcompat/view/menu/u62;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/dr1;->r()Landroidx/appcompat/view/menu/zz1;

    move-result-object v2

    const-string v3, "auto"

    const-string v4, "_ab"

    new-instance v7, Landroid/os/Bundle;

    invoke-direct {v7}, Landroid/os/Bundle;-><init>()V

    invoke-virtual/range {v2 .. v7}, Landroidx/appcompat/view/menu/zz1;->U(Ljava/lang/String;Ljava/lang/String;JLandroid/os/Bundle;)V

    return-void
.end method
