.class public final Landroidx/appcompat/view/menu/c12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/lx;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/u72;

.field public final synthetic b:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;Landroidx/appcompat/view/menu/u72;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/c12;->a:Landroidx/appcompat/view/menu/u72;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 2

    iget-object p1, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/bz1;->n()V

    iget-object p1, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    const/4 v0, 0x0

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/zz1;->Q(Landroidx/appcompat/view/menu/zz1;Z)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/zz1;->r0()V

    iget-object p1, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lt1;->F()Landroidx/appcompat/view/menu/ot1;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/c12;->a:Landroidx/appcompat/view/menu/u72;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u72;->m:Ljava/lang/String;

    const-string v1, "registerTriggerAsync ran. uri"

    invoke-virtual {p1, v1, v0}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    return-void
.end method

.method public final b(Ljava/lang/Throwable;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->n()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/zz1;->Q(Landroidx/appcompat/view/menu/zz1;Z)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/zz1;->r0()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/c12;->b:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "registerTriggerAsync failed with throwable"

    invoke-virtual {v0, v1, p1}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    return-void
.end method
