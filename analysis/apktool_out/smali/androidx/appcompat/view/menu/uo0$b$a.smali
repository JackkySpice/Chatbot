.class public Landroidx/appcompat/view/menu/uo0$b$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/uo0$b;->run()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/of;

.field public final synthetic n:Ljava/lang/Object;

.field public final synthetic o:Landroidx/appcompat/view/menu/uo0$b;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/uo0$b;Landroidx/appcompat/view/menu/of;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/uo0$b$a;->o:Landroidx/appcompat/view/menu/uo0$b;

    iput-object p2, p0, Landroidx/appcompat/view/menu/uo0$b$a;->m:Landroidx/appcompat/view/menu/of;

    iput-object p3, p0, Landroidx/appcompat/view/menu/uo0$b$a;->n:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/uo0$b$a;->m:Landroidx/appcompat/view/menu/of;

    iget-object v1, p0, Landroidx/appcompat/view/menu/uo0$b$a;->n:Ljava/lang/Object;

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/of;->accept(Ljava/lang/Object;)V

    return-void
.end method
