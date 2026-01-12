.class public final Landroidx/appcompat/view/menu/sb1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/df;

.field public final synthetic n:Landroidx/appcompat/view/menu/tb1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/tb1;Landroidx/appcompat/view/menu/df;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/sb1;->m:Landroidx/appcompat/view/menu/df;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    iget-object v1, v0, Landroidx/appcompat/view/menu/tb1;->f:Landroidx/appcompat/view/menu/ey;

    invoke-static {v1}, Landroidx/appcompat/view/menu/ey;->A(Landroidx/appcompat/view/menu/ey;)Ljava/util/Map;

    move-result-object v1

    invoke-static {v0}, Landroidx/appcompat/view/menu/tb1;->e(Landroidx/appcompat/view/menu/tb1;)Landroidx/appcompat/view/menu/q2;

    move-result-object v0

    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/pb1;

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/sb1;->m:Landroidx/appcompat/view/menu/df;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/df;->n()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    iget-object v1, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    const/4 v3, 0x1

    invoke-static {v1, v3}, Landroidx/appcompat/view/menu/tb1;->f(Landroidx/appcompat/view/menu/tb1;Z)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    invoke-static {v1}, Landroidx/appcompat/view/menu/tb1;->d(Landroidx/appcompat/view/menu/tb1;)Landroidx/appcompat/view/menu/l2$f;

    move-result-object v1

    invoke-interface {v1}, Landroidx/appcompat/view/menu/l2$f;->o()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/tb1;->g(Landroidx/appcompat/view/menu/tb1;)V

    return-void

    :cond_1
    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    invoke-static {v1}, Landroidx/appcompat/view/menu/tb1;->d(Landroidx/appcompat/view/menu/tb1;)Landroidx/appcompat/view/menu/l2$f;

    move-result-object v3

    invoke-static {v1}, Landroidx/appcompat/view/menu/tb1;->d(Landroidx/appcompat/view/menu/tb1;)Landroidx/appcompat/view/menu/l2$f;

    move-result-object v1

    invoke-interface {v1}, Landroidx/appcompat/view/menu/l2$f;->b()Ljava/util/Set;

    move-result-object v1

    invoke-interface {v3, v2, v1}, Landroidx/appcompat/view/menu/l2$f;->k(Landroidx/appcompat/view/menu/oz;Ljava/util/Set;)V
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/sb1;->n:Landroidx/appcompat/view/menu/tb1;

    invoke-static {v1}, Landroidx/appcompat/view/menu/tb1;->d(Landroidx/appcompat/view/menu/tb1;)Landroidx/appcompat/view/menu/l2$f;

    move-result-object v1

    const-string v3, "Failed to get service from broker."

    invoke-interface {v1, v3}, Landroidx/appcompat/view/menu/l2$f;->c(Ljava/lang/String;)V

    new-instance v1, Landroidx/appcompat/view/menu/df;

    const/16 v3, 0xa

    invoke-direct {v1, v3}, Landroidx/appcompat/view/menu/df;-><init>(I)V

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/pb1;->G(Landroidx/appcompat/view/menu/df;Ljava/lang/Exception;)V

    return-void

    :cond_2
    iget-object v1, p0, Landroidx/appcompat/view/menu/sb1;->m:Landroidx/appcompat/view/menu/df;

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/pb1;->G(Landroidx/appcompat/view/menu/df;Ljava/lang/Exception;)V

    return-void
.end method
