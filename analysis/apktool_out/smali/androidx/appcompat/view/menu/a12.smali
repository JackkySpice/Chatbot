.class public final Landroidx/appcompat/view/menu/a12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Z

.field public final synthetic n:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;Z)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iput-boolean p2, p0, Landroidx/appcompat/view/menu/a12;->m:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v0, v0, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->p()Z

    move-result v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->o()Z

    move-result v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v2, v2, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    iget-boolean v3, p0, Landroidx/appcompat/view/menu/a12;->m:Z

    invoke-virtual {v2, v3}, Landroidx/appcompat/view/menu/yw1;->m(Z)V

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/a12;->m:Z

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lt1;->K()Landroidx/appcompat/view/menu/ot1;

    move-result-object v1

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/a12;->m:Z

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    const-string v3, "Default data collection state already set to"

    invoke-virtual {v1, v3, v2}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    :cond_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->p()Z

    move-result v1

    if-eq v1, v0, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->p()Z

    move-result v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v2, v2, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/yw1;->o()Z

    move-result v2

    if-eq v1, v2, :cond_2

    :cond_1
    iget-object v1, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, v1, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lt1;->M()Landroidx/appcompat/view/menu/ot1;

    move-result-object v1

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/a12;->m:Z

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    const-string v3, "Default data collection is different than actual status"

    invoke-virtual {v1, v3, v2, v0}, Landroidx/appcompat/view/menu/ot1;->c(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_2
    iget-object v0, p0, Landroidx/appcompat/view/menu/a12;->n:Landroidx/appcompat/view/menu/zz1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/zz1;->w0(Landroidx/appcompat/view/menu/zz1;)V

    return-void
.end method
