.class public final Landroidx/appcompat/view/menu/hw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/wg;
.implements Landroidx/appcompat/view/menu/vh;


# instance fields
.field public final m:Landroidx/appcompat/view/menu/wg;

.field public final n:Landroidx/appcompat/view/menu/jh;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/hw0;->m:Landroidx/appcompat/view/menu/wg;

    iput-object p2, p0, Landroidx/appcompat/view/menu/hw0;->n:Landroidx/appcompat/view/menu/jh;

    return-void
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/jh;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/hw0;->n:Landroidx/appcompat/view/menu/jh;

    return-object v0
.end method

.method public g()Landroidx/appcompat/view/menu/vh;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/hw0;->m:Landroidx/appcompat/view/menu/wg;

    instance-of v1, v0, Landroidx/appcompat/view/menu/vh;

    if-eqz v1, :cond_0

    check-cast v0, Landroidx/appcompat/view/menu/vh;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public n(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/hw0;->m:Landroidx/appcompat/view/menu/wg;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    return-void
.end method
