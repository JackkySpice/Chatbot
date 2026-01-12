.class public final Landroidx/appcompat/view/menu/ir0$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/hw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/ir0;-><init>(Landroidx/appcompat/view/menu/lr0;Landroidx/appcompat/view/menu/x51;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic n:Landroidx/appcompat/view/menu/x51;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/x51;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ir0$a;->n:Landroidx/appcompat/view/menu/x51;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a()Landroidx/appcompat/view/menu/jr0;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ir0$a;->n:Landroidx/appcompat/view/menu/x51;

    invoke-static {v0}, Landroidx/lifecycle/p;->b(Landroidx/appcompat/view/menu/x51;)Landroidx/appcompat/view/menu/jr0;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic d()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ir0$a;->a()Landroidx/appcompat/view/menu/jr0;

    move-result-object v0

    return-object v0
.end method
